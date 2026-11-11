// ISO Builder — servidor HTTP em C++17 (porta do app.py).
//
// Rotas (iguais às do Flask):
//   GET  /                 -> frontend/index.html
//   GET  /sobre.html       -> frontend/sobre.html
//   GET  /<arquivo>        -> arquivos estáticos do frontend (style.css, ...)
//   GET  /progress/<id>    -> {"progress": N, "status": "...", "output": "..."}
//   POST /build/linux      -> multipart: iso, debs (vários), output_dir
//                             responde {"task_id": "..."} e processa em background
//
// Uso:  sudo ./iso-builder [--port 5000] [--frontend DIR] [--base-dir DIR]

#include "httplib.h"
#include "iso_builder.hpp"

#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <csignal>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

// ==========================================================
// Estado global (tarefas em andamento)
// ==========================================================

struct Task {
    int progress = 0;
    std::string status;
    std::optional<std::string> output;
};

static std::map<std::string, Task> g_tasks;
static std::mutex g_tasks_mutex;

static std::string g_base_dir;
static std::string g_upload_dir;
static std::string g_deb_dir;
static std::set<std::string> g_protected_dirs;  // diretórios que NUNCA podem ser pasta de saída

static httplib::Server* g_server = nullptr;

// ==========================================================
// Utilidades
// ==========================================================

static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += char(c);  // UTF-8 passa direto (como o jsonify do Flask)
                }
        }
    }
    return out;
}

static void json_error(httplib::Response& res, int status, const std::string& msg) {
    res.status = status;
    res.set_content("{\"error\": \"" + json_escape(msg) + "\"}", "application/json");
}

static std::string uuid4() {
    static std::mutex m;
    static std::mt19937_64 rng{std::random_device{}()};
    std::lock_guard<std::mutex> lock(m);
    uint64_t a = rng(), b = rng();
    a = (a & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000004000ULL;  // versão 4
    b = (b & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;  // variante RFC 4122
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%08x-%04x-%04x-%04x-%012llx",
                  unsigned(a >> 32), unsigned((a >> 16) & 0xFFFF), unsigned(a & 0xFFFF),
                  unsigned(b >> 48), (unsigned long long)(b & 0xFFFFFFFFFFFFULL));
    return buf;
}

// Home do usuário "de verdade": se rodando via sudo, usa o home de quem
// chamou o sudo (e não /root), para "~" e a pasta de trabalho fazerem sentido.
static std::string user_home() {
    if (const char* su = std::getenv("SUDO_USER")) {
        if (passwd* pw = getpwnam(su)) return pw->pw_dir;
    }
    if (const char* h = std::getenv("HOME")) return h;
    if (passwd* pw = getpwuid(getuid())) return pw->pw_dir;
    return "/root";
}

static std::string abspath(const std::string& p) {
    std::string s = fs::absolute(fs::path(p)).lexically_normal().string();
    while (s.size() > 1 && s.back() == '/') s.pop_back();
    return s;
}

static std::string expand_user(const std::string& path) {
    if (path == "~") return user_home();
    if (path.rfind("~/", 0) == 0) return user_home() + path.substr(1);
    return path;
}

// true se `ancestor` é igual a `path` ou um diretório que contém `path`.
static bool is_same_or_ancestor(const std::string& ancestor, const std::string& path) {
    if (ancestor == path) return true;
    if (ancestor == "/") return true;
    return path.size() > ancestor.size() && path.compare(0, ancestor.size(), ancestor) == 0 &&
           path[ancestor.size()] == '/';
}

// Valida a pasta de saída informada pelo usuário.
//
// ATENÇÃO: o build APAGA todo o conteúdo da pasta de saída antes de extrair a
// ISO. Por isso, além da lista original (/, /etc, /usr, ...), também são
// recusados: o home do usuário e qualquer pasta que CONTENHA o home, a pasta
// de trabalho do programa, e diretórios de sistema comuns (/home, /var, ...).
static std::optional<std::string> validar_diretorio_usuario(const std::string& input) {
    if (input.empty()) return std::nullopt;

    std::string path = abspath(expand_user(input));

    static const char* blocked[] = {
        "/", "/root", "/etc", "/bin", "/usr", "/boot", "/dev", "/proc", "/sys",
        "/sbin", "/lib", "/lib64", "/var", "/opt", "/srv", "/run", "/home", "/mnt",
        "/media", "/tmp",
    };
    for (const char* b : blocked) {
        if (path == b) return std::nullopt;
    }

    // Recusa o home e qualquer ancestral dele, e a pasta de trabalho do programa.
    if (is_same_or_ancestor(path, abspath(user_home()))) return std::nullopt;
    for (const auto& prot : g_protected_dirs) {
        if (is_same_or_ancestor(path, prot)) return std::nullopt;
    }

    std::error_code ec;
    fs::create_directories(path, ec);  // cria a pasta caso não exista
    if (ec || !fs::is_directory(path, ec)) return std::nullopt;

    return path;
}

// Nome de arquivo seguro vindo do upload (remove qualquer caminho, evita ../).
static std::string sanitize_filename(const std::string& name) {
    size_t pos = name.find_last_of("/\\");
    std::string base = (pos == std::string::npos) ? name : name.substr(pos + 1);
    if (base.empty() || base == "." || base == ".." || base.find('\0') != std::string::npos) return "";
    return base;
}

// ==========================================================
// Upload em streaming (a ISO tem GBs: nunca fica inteira na RAM)
// ==========================================================

struct UploadPart {
    std::string name;
    std::string filename;
    std::string value;      // campos de texto (ex.: output_dir)
    std::string tmp_path;   // arquivo temporário (partes com arquivo)
    std::ofstream out;
    bool has_file = false;
};

// Apaga arquivos temporários que sobrarem (erro no meio do upload, etc.).
struct UploadCleanup {
    std::vector<std::unique_ptr<UploadPart>>& parts;
    explicit UploadCleanup(std::vector<std::unique_ptr<UploadPart>>& p) : parts(p) {}
    ~UploadCleanup() {
        for (auto& p : parts) {
            if (p->has_file && !p->tmp_path.empty()) {
                if (p->out.is_open()) p->out.close();
                std::error_code ec;
                fs::remove(p->tmp_path, ec);
            }
        }
    }
};

static bool save_upload(UploadPart& part, const std::string& dest_dir, std::string& final_path) {
    std::string name = sanitize_filename(part.filename);
    if (name.empty()) return false;

    if (part.out.is_open()) part.out.close();

    final_path = dest_dir + "/" + name;
    std::error_code ec;
    fs::rename(part.tmp_path, final_path, ec);
    if (ec) return false;

    chmod(final_path.c_str(), 0644);
    part.tmp_path.clear();  // já foi movido, não apagar
    return true;
}

// ==========================================================
// Handlers
// ==========================================================

static void handle_progress(const httplib::Request& req, httplib::Response& res) {
    std::string id = req.matches[1];

    std::lock_guard<std::mutex> lock(g_tasks_mutex);
    auto it = g_tasks.find(id);
    if (it == g_tasks.end()) {
        json_error(res, 404, "Tarefa não encontrada");
        return;
    }

    const Task& t = it->second;
    std::string body = "{";
    if (t.output) body += "\"output\": \"" + json_escape(*t.output) + "\", ";
    body += "\"progress\": " + std::to_string(t.progress) + ", ";
    body += "\"status\": \"" + json_escape(t.status) + "\"}";
    res.set_content(body, "application/json");
}

static void run_build_task(const std::string& task_id,
                           const std::string& iso_path,
                           const std::string& output_dir,
                           const std::vector<std::string>& packages) {
    auto set_task = [&](auto&& fn) {
        std::lock_guard<std::mutex> lock(g_tasks_mutex);
        fn(g_tasks[task_id]);
    };

    try {
        isob::build_iso(
            iso_path, output_dir,
            [&](int value, const std::string& status) {
                set_task([&](Task& t) { t.progress = value; t.status = status; });
            },
            packages);

        set_task([&](Task& t) {
            t.output = output_dir;
            t.progress = 100;
            t.status = "ISO criada com sucesso!";
        });
    } catch (const std::exception& e) {
        set_task([&](Task& t) { t.status = std::string("Erro: ") + e.what(); });
    } catch (...) {
        set_task([&](Task& t) { t.status = "Erro: falha desconhecida"; });
    }
}

static void handle_build_linux(const httplib::Request& req,
                               httplib::Response& res,
                               const httplib::ContentReader& reader) {
    if (!req.is_multipart_form_data()) {
        json_error(res, 400, "Requisição inválida: esperado multipart/form-data");
        return;
    }

    std::vector<std::unique_ptr<UploadPart>> parts;
    UploadCleanup cleanup(parts);
    bool io_error = false;

    bool ok = reader(
        // início de cada parte do formulário
        [&](const httplib::MultipartFormData& f) {
            auto p = std::make_unique<UploadPart>();
            p->name = f.name;
            p->filename = f.filename;

            if (!f.filename.empty()) {
                std::string tmpl = g_upload_dir + "/.upload-XXXXXX";
                std::vector<char> buf(tmpl.begin(), tmpl.end());
                buf.push_back('\0');
                int fd = mkstemp(buf.data());
                if (fd < 0) { io_error = true; return false; }
                close(fd);

                p->tmp_path = buf.data();
                p->out.open(p->tmp_path, std::ios::binary | std::ios::trunc);
                if (!p->out) { io_error = true; return false; }
                p->has_file = true;
            }
            parts.push_back(std::move(p));
            return true;
        },
        // pedaços de dados da parte atual
        [&](const char* data, size_t len) {
            UploadPart& p = *parts.back();
            if (p.has_file) {
                p.out.write(data, std::streamsize(len));
                if (!p.out) { io_error = true; return false; }
            } else if (p.name == "output_dir") {
                p.value.append(data, len);
            }
            return true;
        });

    if (io_error) {
        json_error(res, 500, "Falha ao gravar o upload em disco");
        return;
    }
    if (!ok) {
        json_error(res, 400, "Upload inválido ou interrompido");
        return;
    }

    UploadPart* iso = nullptr;
    std::string output_dir_raw;
    std::vector<UploadPart*> debs;

    for (auto& p : parts) {
        if (p->name == "iso" && p->has_file && !iso) iso = p.get();
        else if (p->name == "debs" && p->has_file) debs.push_back(p.get());
        else if (p->name == "output_dir") output_dir_raw = p->value;
    }

    if (!iso) {
        json_error(res, 400, "ISO não enviada");
        return;
    }

    auto output_dir = validar_diretorio_usuario(output_dir_raw);
    if (!output_dir) {
        json_error(res, 400, "Diretório inválido");
        return;
    }

    // salva pacotes (.deb / Arch) enviados
    std::vector<std::string> saved_packages;
    for (UploadPart* d : debs) {
        std::string path;
        if (!save_upload(*d, g_deb_dir, path)) {
            json_error(res, 400, "Nome de arquivo inválido: " + d->filename);
            return;
        }
        saved_packages.push_back(path);
    }

    // salva ISO
    std::string iso_path;
    if (!save_upload(*iso, g_upload_dir, iso_path)) {
        json_error(res, 400, "Nome de arquivo inválido: " + iso->filename);
        return;
    }

    // cria ID da tarefa e progresso inicial
    std::string task_id = uuid4();
    {
        std::lock_guard<std::mutex> lock(g_tasks_mutex);
        Task t;
        t.progress = 0;
        t.status = "Iniciando...";
        g_tasks[task_id] = t;
    }

    // roda o build em background
    std::thread(run_build_task, task_id, iso_path, *output_dir, saved_packages).detach();

    res.set_content("{\"task_id\": \"" + task_id + "\"}", "application/json");
}

// ==========================================================
// main
// ==========================================================

static void on_signal(int) {
    if (g_server) g_server->stop();
}

static std::string exe_dir() {
    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return ".";
    buf[n] = '\0';
    return fs::path(buf).parent_path().string();
}

// Procura a pasta do frontend: --frontend, ou ./frontend, ou ao lado do executável.
static std::string find_frontend(const std::string& given) {
    std::vector<std::string> candidates;
    if (!given.empty()) candidates.push_back(given);
    candidates.push_back("frontend");
    candidates.push_back(exe_dir() + "/frontend");
    candidates.push_back(exe_dir() + "/../frontend");

    for (const auto& c : candidates) {
        std::error_code ec;
        if (fs::is_regular_file(fs::path(c) / "index.html", ec)) return abspath(c);
    }
    return "";
}

static void log_request(const httplib::Request& req, const httplib::Response& res) {
    std::time_t now = std::time(nullptr);
    std::tm tm_buf{};
    localtime_r(&now, &tm_buf);
    char ts[64];
    std::strftime(ts, sizeof(ts), "%d/%b/%Y %H:%M:%S", &tm_buf);

    isob::log_line(req.remote_addr + " - - [" + ts + "] \"" + req.method + " " + req.path + " " +
                   req.version + "\" " + std::to_string(res.status) + " -");
}

int main(int argc, char** argv) {
    int port = 5000;
    std::string frontend_arg;
    std::string base_dir_arg;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&](std::string& dst) {
            if (i + 1 >= argc) { std::cerr << "Falta o valor de " << a << "\n"; std::exit(2); }
            dst = argv[++i];
        };
        if (a == "--port") { std::string v; next(v); port = std::atoi(v.c_str()); }
        else if (a == "--frontend") next(frontend_arg);
        else if (a == "--base-dir") next(base_dir_arg);
        else if (a == "-h" || a == "--help") {
            std::cout << "Uso: sudo ./iso-builder [--port 5000] [--frontend DIR] [--base-dir DIR]\n"
                         "  --port      porta HTTP (padrão 5000, escuta apenas em 127.0.0.1)\n"
                         "  --frontend  pasta com index.html/sobre.html/style.css\n"
                         "  --base-dir  pasta de trabalho (padrão: ~/iso_builder do usuário do sudo)\n";
            return 0;
        } else {
            std::cerr << "Argumento desconhecido: " << a << " (use --help)\n";
            return 2;
        }
    }

    // pastas de trabalho
    g_base_dir = abspath(base_dir_arg.empty() ? user_home() + "/iso_builder" : expand_user(base_dir_arg));
    g_upload_dir = g_base_dir + "/uploads";
    g_deb_dir = g_base_dir + "/debs";

    std::error_code ec;
    fs::create_directories(g_upload_dir, ec);
    fs::create_directories(g_deb_dir, ec);
    if (!fs::is_directory(g_upload_dir) || !fs::is_directory(g_deb_dir)) {
        std::cerr << "Não foi possível criar as pastas de trabalho em " << g_base_dir << "\n";
        return 1;
    }
    g_protected_dirs = {g_base_dir, g_upload_dir, g_deb_dir};

    std::string frontend = find_frontend(frontend_arg);
    if (frontend.empty()) {
        std::cerr << "Pasta 'frontend' (com index.html) não encontrada. Use --frontend DIR.\n";
        return 1;
    }

    if (geteuid() != 0) {
        std::cerr << "AVISO: não está rodando como root. O servidor sobe, mas o build vai falhar.\n"
                     "       Inicie com:  sudo ./iso-builder\n";
    }

    httplib::Server svr;
    g_server = &svr;

    svr.set_payload_max_length(size_t(64) * 1024 * 1024 * 1024);  // ISOs grandes
    svr.set_read_timeout(60, 0);
    svr.set_write_timeout(60, 0);
    svr.set_tcp_nodelay(true);
    svr.set_logger(log_request);

    // arquivos estáticos (index.html em "/", sobre.html, style.css, ...)
    if (!svr.set_mount_point("/", frontend)) {
        std::cerr << "Falha ao servir a pasta do frontend: " << frontend << "\n";
        return 1;
    }

    svr.Get(R"(/progress/(.+))", handle_progress);
    svr.Post("/build/linux", handle_build_linux);

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    isob::log_line(" * ISO Builder (C++) — pasta de trabalho: " + g_base_dir);
    isob::log_line(" * Frontend: " + frontend);
    isob::log_line(" * Running on http://127.0.0.1:" + std::to_string(port));
    isob::log_line("Press CTRL+C to quit");

    if (!svr.listen("127.0.0.1", port)) {
        std::cerr << "Não foi possível escutar em 127.0.0.1:" << port
                  << " (porta em uso? tente --port 5001)\n";
        return 1;
    }

    isob::log_line("Servidor encerrado.");
    return 0;
}
