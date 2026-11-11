// ISO Builder — implementação do núcleo (porta fiel do iso_linux.py).
//
// As mensagens de log ("DEBUG ...", "+ comando") foram mantidas iguais às da
// versão Python para facilitar a comparação de logs entre as duas versões.

#include "iso_builder.hpp"
#include "sha512.hpp"

#include <fcntl.h>
#include <limits.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <optional>
#include <regex>
#include <sstream>
#include <utility>

extern char** environ;

namespace fs = std::filesystem;

namespace isob {

// ==========================================================
// Log
// ==========================================================

static std::mutex g_log_mutex;

void log_line(const std::string& line) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    std::cout << line << std::endl;
}

namespace {

// ==========================================================
// Utilidades
// ==========================================================

void report_progress(const ProgressCallback& cb, int percent, const std::string& message) {
    if (cb) cb(percent, message);
}

// O processo de criação da ISO precisa estar executando como root.
// (Este código NÃO usa sudo internamente, para não travar esperando senha.)
void require_root() {
    if (geteuid() != 0) {
        throw BuildError(
            "O processo de criação da ISO precisa ser executado como root.\n\n"
            "Inicie o backend com:\n"
            "    sudo ./iso-builder\n\n"
            "O ISO Builder não executa sudo internamente.");
    }
}

std::string join(const std::vector<std::string>& v, const std::string& sep) {
    std::string out;
    for (size_t i = 0; i < v.size(); i++) {
        if (i) out += sep;
        out += v[i];
    }
    return out;
}

// Mesmo formato da mensagem do CalledProcessError do Python:
//   Command '['chroot', '/x', ...]' returned non-zero exit status 1.
std::string py_list_repr(const std::vector<std::string>& v) {
    std::string out = "[";
    for (size_t i = 0; i < v.size(); i++) {
        if (i) out += ", ";
        out += "'" + v[i] + "'";
    }
    return out + "]";
}

struct RunResult {
    int returncode = 0;
    std::string output;  // stdout+stderr combinados (somente se capture=true)
};

// Executa um comando externo (sem shell, via posix_spawnp).
//   check   : se true, lança erro quando o código de saída não está em `allow`
//   capture : captura stdout+stderr em vez de herdar o terminal
RunResult run(const std::vector<std::string>& cmd,
              bool check = true,
              const std::vector<int>& allow = {0},
              bool capture = false) {
    log_line("+ " + join(cmd, " "));

    std::vector<char*> argv;
    for (const auto& s : cmd) argv.push_back(const_cast<char*>(s.c_str()));
    argv.push_back(nullptr);

    int outpipe[2] = {-1, -1};
    if (capture && pipe2(outpipe, O_CLOEXEC) != 0) {
        throw BuildError(std::string("pipe2 falhou: ") + std::strerror(errno));
    }

    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    if (capture) {
        posix_spawn_file_actions_adddup2(&fa, outpipe[1], 1);
        posix_spawn_file_actions_adddup2(&fa, outpipe[1], 2);
    }

    pid_t pid = 0;
    int rc = posix_spawnp(&pid, argv[0], &fa, nullptr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&fa);

    if (capture) close(outpipe[1]);

    if (rc != 0) {
        if (capture) close(outpipe[0]);
        throw BuildError("[Errno " + std::to_string(rc) + "] " + std::strerror(rc) +
                         ": '" + cmd[0] + "'");
    }

    RunResult result;
    if (capture) {
        char buf[4096];
        ssize_t n;
        while ((n = read(outpipe[0], buf, sizeof(buf))) > 0 || (n < 0 && errno == EINTR)) {
            if (n > 0) result.output.append(buf, size_t(n));
        }
        close(outpipe[0]);
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) break;
    }

    if (WIFEXITED(status)) result.returncode = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) result.returncode = -WTERMSIG(status);
    else result.returncode = -1;

    if (check && std::find(allow.begin(), allow.end(), result.returncode) == allow.end()) {
        throw BuildError("Command '" + py_list_repr(cmd) + "' returned non-zero exit status " +
                         std::to_string(result.returncode) + ".");
    }
    return result;
}

bool has_executable(const std::string& name) {
    const char* path_env = std::getenv("PATH");
    std::string path = path_env ? path_env : "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    std::stringstream ss(path);
    std::string dir;
    while (std::getline(ss, dir, ':')) {
        if (dir.empty()) continue;
        fs::path candidate = fs::path(dir) / name;
        std::error_code ec;
        if (fs::is_regular_file(candidate, ec) && access(candidate.c_str(), X_OK) == 0) return true;
    }
    return false;
}

// --- helpers de sistema de arquivos (equivalentes aos de os.path) ---

bool is_file(const std::string& p)  { std::error_code ec; return fs::is_regular_file(p, ec); }
bool is_dir(const std::string& p)   { std::error_code ec; return fs::is_directory(p, ec); }
bool path_exists(const std::string& p) { std::error_code ec; return fs::exists(p, ec); }
bool path_lexists(const std::string& p) {
    std::error_code ec;
    auto st = fs::symlink_status(p, ec);
    return !ec && st.type() != fs::file_type::not_found;
}
bool is_symlink(const std::string& p) { std::error_code ec; return fs::is_symlink(p, ec); }

std::string abspath(const std::string& p) {
    std::string s = fs::absolute(fs::path(p)).lexically_normal().string();
    while (s.size() > 1 && s.back() == '/') s.pop_back();
    return s;
}

std::string real_path(const std::string& p) {
    char buf[PATH_MAX];
    if (realpath(p.c_str(), buf)) return buf;
    return abspath(p);
}

std::string path_join(const std::string& a, const std::string& b) {
    return (fs::path(a) / b).string();
}

// Remove arquivo, link ou diretório (usa rm, como a versão Python).
void remove_path(const std::string& path) {
    if (!path_lexists(path)) return;
    if (is_dir(path) && !is_symlink(path)) run({"rm", "-rf", path});
    else run({"rm", "-f", path});
}

void ensure_directory(const std::string& path) {
    std::error_code ec;
    fs::create_directories(path, ec);
    if (ec && !is_dir(path)) {
        throw BuildError("Não foi possível criar o diretório " + path + ": " + ec.message());
    }
    if (!is_dir(path)) {
        throw BuildError("O caminho existe mas não é um diretório: " + path);
    }
}

std::string size_mb(uintmax_t bytes) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%.2f", double(bytes) / (1024.0 * 1024.0));
    return buf;
}

std::string size_gb(uintmax_t bytes) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%.2f", double(bytes) / (1024.0 * 1024.0 * 1024.0));
    return buf;
}

// Diretório temporário que se apaga sozinho (equivalente ao try/finally + rmtree).
struct TempDir {
    std::string path;
    TempDir() = default;
    explicit TempDir(std::string p) : path(std::move(p)) {}
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
    ~TempDir() {
        if (!path.empty()) {
            std::error_code ec;
            fs::remove_all(path, ec);
        }
    }
};

// Cria um diretório temporário. Prefere o diretório PAI de `near` (mesmo
// filesystem do destino => mover a ISO final é um rename instantâneo e não
// depende de /tmp, que em algumas distros — ex.: Fedora — é um tmpfs em RAM).
// Se não for possível, usa o diretório temporário do sistema.
std::string make_temp_dir(const std::string& prefix, const std::string& near) {
    std::vector<std::string> bases;
    fs::path parent = fs::path(near).parent_path();
    if (!parent.empty()) bases.push_back(parent.string());
    std::error_code ec;
    bases.push_back(fs::temp_directory_path(ec).string());

    for (const auto& base : bases) {
        std::string tmpl = base + "/." + prefix + "XXXXXX";
        std::vector<char> buf(tmpl.begin(), tmpl.end());
        buf.push_back('\0');
        if (mkdtemp(buf.data())) return std::string(buf.data());
    }
    throw BuildError("Não foi possível criar um diretório temporário.");
}

// Move um arquivo (rename; se for entre filesystems, copia e remove a origem).
void move_file(const std::string& src, const std::string& dst) {
    std::error_code ec;
    fs::rename(src, dst, ec);
    if (!ec) return;
    fs::copy_file(src, dst, fs::copy_options::overwrite_existing, ec);
    if (ec) throw BuildError("Falha ao mover " + src + " para " + dst + ": " + ec.message());
    fs::remove(src, ec);
}

// Verifica se um caminho está atualmente montado, lendo /proc/mounts
// diretamente (não depende de findmnt). Usado para confirmar que um "umount"
// realmente funcionou antes de seguir para o mksquashfs.
bool is_mounted(const std::string& path) {
    std::string target = real_path(path);

    std::ifstream mounts("/proc/mounts");
    if (!mounts) return false;

    std::string line;
    while (std::getline(mounts, line)) {
        std::istringstream iss(line);
        std::string dev, mp;
        if (!(iss >> dev >> mp)) continue;

        // /proc/mounts escapa caracteres especiais como \040 (espaço)
        std::string decoded;
        for (size_t i = 0; i < mp.size(); i++) {
            if (mp[i] == '\\' && i + 3 < mp.size() &&
                std::isdigit((unsigned char)mp[i + 1]) &&
                std::isdigit((unsigned char)mp[i + 2]) &&
                std::isdigit((unsigned char)mp[i + 3])) {
                decoded.push_back(char(std::stoi(mp.substr(i + 1, 3), nullptr, 8)));
                i += 3;
            } else {
                decoded.push_back(mp[i]);
            }
        }
        if (real_path(decoded) == target) return true;
    }
    return false;
}

// ==========================================================
// Dependências
// ==========================================================

void validate_dependencies() {
    static const char* required[] = {
        "7z", "unsquashfs", "mksquashfs", "xorriso",
        "mount", "umount", "chroot", "rsync",
    };
    std::vector<std::string> missing;
    for (const char* exe : required) {
        if (!has_executable(exe)) missing.push_back(exe);
    }
    if (!missing.empty()) {
        throw BuildError("Dependências não encontradas: " + join(missing, ", "));
    }
}

// Procura pelo isohdpfx.bin usado na criação de ISOs híbridas BIOS/MBR.
// Usado somente no fluxo Debian/Ubuntu.
std::string find_isohdpfx() {
    static const char* possible[] = {
        "/usr/lib/ISOLINUX/isohdpfx.bin",
        "/usr/lib/syslinux/isohdpfx.bin",
        "/usr/lib/syslinux/bios/isohdpfx.bin",
        "/usr/share/syslinux/isohdpfx.bin",
        "/usr/share/syslinux/bios/isohdpfx.bin",
    };
    for (const char* p : possible) {
        if (is_file(p)) return p;
    }
    throw BuildError("isohdpfx.bin não encontrado. Instale o pacote syslinux.");
}

// ==========================================================
// Extração da ISO
// ==========================================================

// Extrai o conteúdo completo da ISO usando xorriso (osirrox), que preserva
// symlinks/permissões/Rock Ridge com fidelidade (o 7z não faz isso direito).
void extract_iso(const std::string& iso_path_in, const std::string& out_dir_in) {
    std::string iso_path = abspath(iso_path_in);
    std::string out_dir = abspath(out_dir_in);

    if (!is_file(iso_path)) throw BuildError("ISO não encontrada: " + iso_path);

    ensure_directory(out_dir);

    run({"xorriso", "-osirrox", "on", "-indev", iso_path, "-extract", "/", out_dir});
}

// Fallback caso o xorriso falhe na extração.
void extract_with_7z(const std::string& iso_path_in, const std::string& out_dir_in) {
    if (!has_executable("7z")) throw BuildError("7z não encontrado no PATH.");

    std::string iso_path = abspath(iso_path_in);
    std::string out_dir = abspath(out_dir_in);

    if (!is_file(iso_path)) throw BuildError("ISO não encontrada: " + iso_path);

    ensure_directory(out_dir);

    run({"7z", "x", "-y", "-o" + out_dir, iso_path});
}

// ==========================================================
// SquashFS
// ==========================================================

// Detecta o SquashFS presente na ISO.
//   Debian/Ubuntu: casper/filesystem.squashfs, live/filesystem.squashfs
//   Arch:          arch/x86_64/airootfs.sfs
std::string detect_squashfs(const std::string& iso_root_in) {
    std::string iso_root = abspath(iso_root_in);

    const std::vector<std::string> candidates = {
        iso_root + "/casper/filesystem.squashfs",
        iso_root + "/live/filesystem.squashfs",
        iso_root + "/arch/x86_64/airootfs.sfs",
    };

    for (const auto& path : candidates) {
        if (is_file(path)) {
            std::string p = abspath(path);
            log_line("DEBUG SquashFS encontrado: " + p);
            return p;
        }
    }
    throw BuildError("Filesystem SquashFS não encontrado na ISO.");
}

bool ends_with(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// Detecta a família da distribuição com base na localização do SquashFS.
std::string detect_distro(const std::string& iso_root) {
    std::string sq = detect_squashfs(iso_root);

    if (sq.find("/casper/filesystem.squashfs") != std::string::npos ||
        sq.find("/live/filesystem.squashfs") != std::string::npos) {
        log_line("DEBUG distribuição detectada: Debian/Ubuntu");
        return "debian";
    }
    if (ends_with(sq, "/arch/x86_64/airootfs.sfs")) {
        log_line("DEBUG distribuição detectada: Arch");
        return "arch";
    }
    throw BuildError("Não foi possível determinar a distribuição.");
}

// Detecta a compressão usada pelo SquashFS original.
std::string detect_squashfs_compression(const std::string& squashfs_path) {
    RunResult r = run({"unsquashfs", "-s", squashfs_path}, true, {0}, true);

    std::regex re(R"(Compression\s+([A-Za-z0-9_-]+))", std::regex::icase);
    std::smatch m;
    if (std::regex_search(r.output, m, re)) {
        std::string comp = m[1].str();
        std::transform(comp.begin(), comp.end(), comp.begin(),
                       [](unsigned char c) { return char(std::tolower(c)); });
        static const char* allowed[] = {"xz", "zstd", "gzip", "lzo", "lz4", "lzma"};
        for (const char* a : allowed) {
            if (comp == a) {
                log_line("DEBUG compressão SquashFS detectada: " + comp);
                return comp;
            }
        }
    }
    log_line("WARNING: não foi possível detectar a compressão do SquashFS. Usando xz.");
    return "xz";
}

// ==========================================================
// Chroot
// ==========================================================

void prepare_chroot(const std::string& work_dir) {
    require_root();
    for (const char* d : {"dev", "proc", "sys", "run"}) {
        run({"mkdir", "-p", path_join(work_dir, d)});
    }
}

// Estado original do /etc/resolv.conf do sistema Live (para restaurar depois).
struct DnsState {
    bool existed = false;
    bool is_symlink = false;
    std::string target;
    std::string backup;
};

// Copia o resolv.conf do host para dentro do sistema Live TEMPORARIAMENTE,
// só para a instalação de pacotes ter DNS. restore_dns() desfaz isso, para a
// ISO final não carregar a configuração de rede do computador do build.
DnsState configure_dns(const std::string& work_dir) {
    require_root();
    DnsState state;
    std::string resolv_conf = work_dir + "/etc/resolv.conf";

    try {
        if (is_symlink(resolv_conf)) {
            state.existed = true;
            state.is_symlink = true;
            state.target = fs::read_symlink(resolv_conf).string();
        } else if (is_file(resolv_conf)) {
            state.existed = true;
            std::string backup = resolv_conf + ".isobuilder-backup";
            fs::copy_file(resolv_conf, backup, fs::copy_options::overwrite_existing);
            state.backup = backup;
        }

        run({"rm", "-f", resolv_conf}, false);
        run({"cp", "/etc/resolv.conf", resolv_conf});

        log_line("DEBUG DNS configurado temporariamente.");
    } catch (const std::exception& e) {
        log_line(std::string("WARNING: não foi possível configurar DNS: ") + e.what());
    }
    return state;
}

// Restaura o /etc/resolv.conf original do sistema Live.
void restore_dns(const std::string& work_dir, const DnsState& state) {
    std::string resolv_conf = work_dir + "/etc/resolv.conf";

    try {
        run({"rm", "-f", resolv_conf}, false);

        if (state.is_symlink && !state.target.empty()) {
            fs::create_symlink(state.target, resolv_conf);
        } else if (!state.backup.empty() && is_file(state.backup)) {
            fs::rename(state.backup, resolv_conf);
        }
        // Se não existia antes, simplesmente permanece removido.

        log_line("DEBUG DNS original do sistema Live restaurado.");
    } catch (const std::exception& e) {
        log_line(std::string("WARNING: não foi possível restaurar o DNS original: ") + e.what());
    }
}

// Remove vestígios da instalação antes de recriar o SquashFS:
//  - locks do dpkg/pacman residuais;
//  - /etc/machine-id vazio (systemd gera um novo no primeiro boot; sem isso
//    toda cópia da ISO compartilharia o mesmo machine-id).
void cleanup_chroot_traces(const std::string& work_dir, const std::string& distro) {
    require_root();

    std::string machine_id = work_dir + "/etc/machine-id";
    if (is_file(machine_id)) {
        std::ofstream f(machine_id, std::ios::trunc);
        if (f) log_line("DEBUG machine-id resetado para o primeiro boot.");
        else log_line("WARNING: não foi possível resetar machine-id");
    }

    std::vector<std::string> locks;
    if (distro == "debian") {
        locks = {
            work_dir + "/var/lib/dpkg/lock",
            work_dir + "/var/lib/dpkg/lock-frontend",
            work_dir + "/var/cache/apt/archives/lock",
        };
    } else if (distro == "arch") {
        locks = {work_dir + "/var/lib/pacman/db.lck"};
    }

    for (const auto& lock : locks) {
        if (path_exists(lock)) {
            log_line("DEBUG removendo lock residual: " + lock);
            remove_path(lock);
        }
    }
}

// Garante que /etc/mtab dentro do chroot seja um symlink para
// /proc/self/mounts (o pacman lê esse arquivo para calcular espaço livre).
// Só faz sentido DEPOIS de montar /proc dentro do work_dir.
void ensure_mtab_symlink(const std::string& work_dir) {
    require_root();
    std::string mtab = work_dir + "/etc/mtab";

    try {
        if (is_symlink(mtab)) {
            std::string current = fs::read_symlink(mtab).string();
            if (current == "/proc/self/mounts" || current == "../proc/self/mounts") return;
        }
        if (path_lexists(mtab)) remove_path(mtab);

        fs::create_symlink("/proc/self/mounts", mtab);
        log_line("DEBUG /etc/mtab apontado para /proc/self/mounts.");
    } catch (const std::exception& e) {
        log_line(std::string("WARNING: não foi possível criar symlink de /etc/mtab: ") + e.what());
    }
}

using MountList = std::vector<std::pair<std::string, std::string>>;  // ("recursive"|"normal", ponto)

// Desmonta os pseudo-filesystems do chroot na ordem inversa da montagem.
//
// Confirma (lendo /proc/mounts) que cada ponto realmente saiu, tenta
// "umount -l" (lazy) como segunda chance e, se ainda assim sobrar algo
// montado, ABORTA com erro — em vez de seguir e empacotar o /dev, /proc,
// /sys ou /run do computador hospedeiro dentro da ISO final.
void unmount_chroot_filesystems(const MountList& mounted) {
    require_root();

    std::vector<std::string> failures;

    for (auto it = mounted.rbegin(); it != mounted.rend(); ++it) {
        const std::string& type = it->first;
        const std::string& mp = it->second;

        if (type == "recursive") run({"umount", "-R", mp}, false);
        else run({"umount", mp}, false);

        if (is_mounted(mp)) {
            log_line("WARNING: " + mp + " continua montado após umount normal, tentando desmonte lazy (-l)...");
            run({"umount", "-l", mp}, false);
        }
        if (is_mounted(mp)) failures.push_back(mp);
    }

    if (!failures.empty()) {
        throw BuildError(
            "Falha ao desmontar os seguintes pontos do chroot: " + join(failures, ", ") +
            ". O processo foi interrompido para evitar gerar um SquashFS corrompido com "
            "arquivos do sistema hospedeiro. Verifique processos presos com "
            "'lsof +D <caminho>' ou 'fuser -vm <caminho>' e tente novamente.");
    }
}

// Monta os pseudo-filesystems necessários para o chroot.
MountList mount_chroot_filesystems(const std::string& work_dir) {
    require_root();

    std::string dev_dir = path_join(work_dir, "dev");
    std::string proc_dir = path_join(work_dir, "proc");
    std::string sys_dir = path_join(work_dir, "sys");
    std::string run_dir = path_join(work_dir, "run");

    MountList mounted;

    try {
        // Auto-bind do próprio work_dir.
        // Um "chroot" comum não faz o diretório virar um ponto de montagem de
        // verdade. O pacman precisa achar em /proc/self/mounts uma entrada
        // para o "/" visto de dentro do chroot; sem isso falha com
        // "could not determine root mount point /" / "not enough free disk
        // space". É o que o arch-chroot faz por baixo dos panos.
        run({"mount", "--bind", work_dir, work_dir});
        run({"mount", "--make-private", work_dir});
        mounted.emplace_back("normal", work_dir);

        // /dev
        run({"mount", "--rbind", "/dev", dev_dir});
        run({"mount", "--make-rslave", dev_dir});
        mounted.emplace_back("recursive", dev_dir);

        // /proc
        run({"mount", "-t", "proc", "proc", proc_dir});
        mounted.emplace_back("normal", proc_dir);

        // /etc/mtab -> /proc/self/mounts (depois de montar /proc)
        ensure_mtab_symlink(work_dir);

        // /sys
        run({"mount", "--rbind", "/sys", sys_dir});
        run({"mount", "--make-rslave", sys_dir});
        mounted.emplace_back("recursive", sys_dir);

        // /run
        run({"mount", "--rbind", "/run", run_dir});
        run({"mount", "--make-rslave", run_dir});
        mounted.emplace_back("recursive", run_dir);

        return mounted;
    } catch (...) {
        try {
            unmount_chroot_filesystems(mounted);
        } catch (...) {
            // mantém o erro original
        }
        throw;
    }
}

// Testa se o sistema extraído consegue iniciar um chroot.
void test_chroot(const std::string& work_dir) {
    require_root();
    run({"chroot", work_dir, "/bin/bash", "-c",
         "echo CHROOT_OK && cat /etc/os-release | head -5"});
    log_line("DEBUG ambiente chroot funcionando.");
}

// ==========================================================
// Pacotes
// ==========================================================

std::vector<std::string> validate_packages(const std::vector<std::string>& package_paths) {
    std::vector<std::string> validated;
    for (const auto& p : package_paths) {
        std::string abs = abspath(p);
        if (!is_file(abs)) throw BuildError("Pacote não encontrado: " + abs);
        validated.push_back(abs);
    }
    return validated;
}

// Copia os pacotes para dentro do sistema extraído.
// Retorna (diretório dentro do chroot, nomes dos arquivos).
std::pair<std::string, std::vector<std::string>>
copy_packages_to_chroot(const std::string& work_dir, const std::vector<std::string>& package_paths) {
    require_root();

    std::string package_dir = work_dir + "/tmp/packages";
    run({"mkdir", "-p", package_dir});

    std::vector<std::string> names;
    for (const auto& p : package_paths) {
        names.push_back(fs::path(p).filename().string());
        run({"cp", p, package_dir});
    }
    return {package_dir, names};
}

std::vector<std::string> chroot_package_files(const std::vector<std::string>& names) {
    std::vector<std::string> files;
    for (const auto& n : names) files.push_back("/tmp/packages/" + n);
    return files;
}

// Instala arquivos .deb dentro de um sistema Debian/Ubuntu.
void install_debian_packages(const std::string& work_dir,
                             const std::vector<std::string>& names,
                             const ProgressCallback& cb) {
    require_root();
    report_progress(cb, 97, "Instalando pacotes Debian/Ubuntu...");

    std::vector<std::string> cmd = {"chroot", work_dir, "dpkg", "-i"};
    for (const auto& f : chroot_package_files(names)) cmd.push_back(f);

    RunResult r = run(cmd, false);
    log_line("DEBUG código dpkg: " + std::to_string(r.returncode));

    run({"chroot", work_dir, "apt-get", "-f", "install", "-y"});
}

// Instala pacotes Arch dentro do sistema extraído.
void install_arch_packages(const std::string& work_dir,
                           const std::vector<std::string>& names,
                           const ProgressCallback& cb) {
    require_root();
    report_progress(cb, 97, "Instalando pacotes Arch...");

    std::vector<std::string> cmd = {"chroot", work_dir, "pacman", "-U", "--noconfirm"};
    for (const auto& f : chroot_package_files(names)) cmd.push_back(f);

    run(cmd);
}

void remove_temporary_packages(const std::string& work_dir) {
    std::string package_dir = work_dir + "/tmp/packages";
    if (path_exists(package_dir)) {
        log_line("DEBUG removendo pacotes temporários: " + package_dir);
        remove_path(package_dir);
    }
}

// ==========================================================
// Personalização
// ==========================================================

struct CustomizeResult {
    std::string distro;
    std::string squashfs_path;
    std::string squashfs_compression;
    std::string work_dir;
};

// Extrai o SquashFS e personaliza o sistema Live.
CustomizeResult customize_live_system(const std::string& iso_root_in,
                                      const std::vector<std::string>& package_paths_in,
                                      const ProgressCallback& cb) {
    require_root();

    std::string iso_root = abspath(iso_root_in);
    std::vector<std::string> package_paths = validate_packages(package_paths_in);

    if (package_paths.empty()) {
        throw BuildError("Nenhum pacote foi informado para personalização.");
    }

    std::string squashfs_path = detect_squashfs(iso_root);
    std::string distro = detect_distro(iso_root);
    std::string compression = detect_squashfs_compression(squashfs_path);
    std::string work_dir = iso_root + "/squashfs-root";

    log_line("DEBUG distribuição: " + distro);
    log_line("DEBUG SquashFS: " + squashfs_path);
    log_line("DEBUG compressão SquashFS: " + compression);
    log_line("DEBUG diretório de trabalho: " + work_dir);

    // Remove extração anterior
    if (path_exists(work_dir)) {
        log_line("DEBUG removendo extração anterior: " + work_dir);
        remove_path(work_dir);
    }

    // Extrai SquashFS
    report_progress(cb, 88, "Extraindo sistema interno (SquashFS)...");
    run({"unsquashfs", "-d", work_dir, squashfs_path});

    if (!is_dir(work_dir)) throw BuildError("Falha ao extrair SquashFS: " + work_dir);

    prepare_chroot(work_dir);
    DnsState dns_state = configure_dns(work_dir);

    MountList mounted;
    std::exception_ptr pending;  // equivalente ao try/finally do Python

    try {
        report_progress(cb, 90, "Montando ambiente chroot...");
        mounted = mount_chroot_filesystems(work_dir);

        report_progress(cb, 95, "Testando ambiente chroot...");
        test_chroot(work_dir);

        auto [package_dir, package_names] = copy_packages_to_chroot(work_dir, package_paths);
        log_line("DEBUG diretório temporário: " + package_dir);

        if (distro == "debian") install_debian_packages(work_dir, package_names, cb);
        else if (distro == "arch") install_arch_packages(work_dir, package_names, cb);
        else throw BuildError("Distribuição não suportada: " + distro);

        // Limpeza de vestígios e restauração do DNS ainda com tudo montado.
        cleanup_chroot_traces(work_dir, distro);
        restore_dns(work_dir, dns_state);
    } catch (...) {
        pending = std::current_exception();
    }

    // "finally": SEMPRE desmonta. Se o desmonte falhar, esse erro prevalece
    // (igual ao Python) para nunca seguir adiante com algo ainda montado.
    report_progress(cb, 98, "Desmontando ambiente chroot...");
    unmount_chroot_filesystems(mounted);
    log_line("DEBUG ambiente chroot desmontado.");

    if (pending) std::rethrow_exception(pending);

    remove_temporary_packages(work_dir);

    report_progress(cb, 98, "Sistema personalizado com sucesso.");
    log_line("DEBUG personalização concluída.");

    return {distro, squashfs_path, compression, work_dir};
}

// ==========================================================
// Reconstrução do SquashFS
// ==========================================================

// Reconstrói o SquashFS preservando a compressão original.
void rebuild_squashfs(const std::string& squashfs_path_in,
                      const std::string& work_dir_in,
                      const ProgressCallback& cb,
                      std::string compression) {
    require_root();

    std::string squashfs_path = abspath(squashfs_path_in);
    std::string work_dir = abspath(work_dir_in);

    if (!is_dir(work_dir)) throw BuildError("Diretório do sistema não encontrado: " + work_dir);

    // Rede de segurança: mesmo com o desmonte já validado, confere de novo que
    // dev/proc/sys/run NÃO estão montados antes de empacotar.
    for (const char* sensitive : {"dev", "proc", "sys", "run"}) {
        std::string full = path_join(work_dir, sensitive);
        if (is_mounted(full)) {
            throw BuildError(full + " ainda está montado. Abortando a reconstrução do SquashFS "
                                    "para não empacotar arquivos do sistema hospedeiro dentro da ISO.");
        }
    }

    if (compression.empty()) compression = detect_squashfs_compression(squashfs_path);

    report_progress(cb, 98, "Recriando sistema SquashFS...");

    std::string temp_squashfs = squashfs_path + ".new";
    if (path_exists(temp_squashfs)) remove_path(temp_squashfs);

    try {
        log_line("DEBUG criando SquashFS temporário: " + temp_squashfs);
        log_line("DEBUG usando compressão SquashFS: " + compression);

        run({"mksquashfs", work_dir, temp_squashfs,
             "-comp", compression, "-noappend",
             "-wildcards", "-e", "dev/*", "proc/*", "sys/*", "run/*"});

        if (!is_file(temp_squashfs)) throw BuildError("mksquashfs não criou o arquivo temporário.");

        std::error_code ec;
        uintmax_t size = fs::file_size(temp_squashfs, ec);
        if (ec || size == 0) throw BuildError("SquashFS temporário está vazio.");

        log_line("DEBUG novo SquashFS: " + size_mb(size) + " MB");

        run({"unsquashfs", "-s", temp_squashfs});

        log_line("DEBUG substituindo SquashFS original: " + squashfs_path);
        run({"mv", temp_squashfs, squashfs_path});
    } catch (...) {
        if (path_exists(temp_squashfs)) {
            try { remove_path(temp_squashfs); } catch (...) {}
        }
        throw;
    }

    report_progress(cb, 99, "SquashFS recriado com sucesso.");
}

// ==========================================================
// Arquivos auxiliares do Arch
// ==========================================================

// Atualiza o SHA-512 do airootfs.sfs da ISO Arch.
void update_arch_squashfs_checksum(const std::string& iso_root, const std::string& squashfs_path) {
    std::string relative = fs::path(squashfs_path).lexically_relative(iso_root).generic_string();
    std::string checksum_path = iso_root + "/arch/x86_64/airootfs.sha512";

    ensure_directory(fs::path(checksum_path).parent_path().string());

    Sha512 sha;
    {
        std::ifstream src(squashfs_path, std::ios::binary);
        if (!src) throw BuildError("Não foi possível ler " + squashfs_path);
        std::vector<char> buf(1024 * 1024);
        while (src) {
            src.read(buf.data(), std::streamsize(buf.size()));
            std::streamsize got = src.gcount();
            if (got > 0) sha.update(buf.data(), size_t(got));
        }
    }
    std::string digest = sha.hexdigest();

    std::ofstream out(checksum_path, std::ios::trunc);
    if (!out) throw BuildError("Não foi possível escrever " + checksum_path);
    out << digest << "  " << relative << "\n";

    log_line("DEBUG checksum SHA-512 atualizado: " + checksum_path);
}

// Remove backups antigos do airootfs.sfs.
void remove_arch_backup_files(const std::string& iso_root) {
    std::string p = iso_root + "/arch/x86_64/airootfs.sfs.backup";
    if (path_exists(p)) {
        log_line("DEBUG removendo backup do Arch: " + p);
        remove_path(p);
    }
}

// ==========================================================
// Boot Debian / Ubuntu
// ==========================================================

std::optional<std::string> find_existing_file(const std::string& iso_root,
                                              const std::vector<std::string>& candidates) {
    for (const auto& c : candidates) {
        if (is_file(iso_root + "/" + c)) return c;
    }
    return std::nullopt;
}

struct BootConfig {
    std::string type;          // "syslinux" ou "grub"
    std::string boot_image;
    std::string boot_catalog;
    std::string efi_image;
};

// Detecta a estrutura de boot usada pelo fluxo Debian/Ubuntu.
BootConfig detect_boot_config(const std::string& iso_root_in) {
    std::string iso_root = abspath(iso_root_in);

    const std::vector<std::string> efi_candidates = {
        "EFI/BOOT/BOOTX64.EFI", "EFI/BOOT/BOOTx64.EFI", "EFI/BOOT/bootx64.efi",
        "EFI/boot/BOOTX64.EFI", "EFI/boot/BOOTx64.EFI", "EFI/boot/bootx64.efi",
        "EFI/BOOT/grubx64.efi", "EFI/boot/grubx64.efi",
    };

    auto efi_image = find_existing_file(iso_root, efi_candidates);
    if (!efi_image) throw BuildError("Imagem EFI não encontrada na ISO.");

    // syslinux/isolinux: só a imagem de boot precisa existir; o catálogo
    // (boot.cat) é apenas o DESTINO que o xorriso vai escrever com "-c".
    const std::vector<std::pair<std::string, std::string>> syslinux_pairs = {
        {"isolinux/isolinux.bin", "isolinux/boot.cat"},
        {"boot/isolinux/isolinux.bin", "boot/isolinux/boot.cat"},
        {"boot/syslinux/isolinux.bin", "boot/syslinux/boot.cat"},
        {"syslinux/isolinux.bin", "syslinux/boot.cat"},
    };

    for (const auto& [boot_candidate, catalog_candidate] : syslinux_pairs) {
        if (is_file(iso_root + "/" + boot_candidate)) {
            log_line("DEBUG bootloader: ISOLINUX/SYSLINUX");
            return {"syslinux", boot_candidate, catalog_candidate, *efi_image};
        }
    }

    auto grub = find_existing_file(iso_root, {"boot/grub/i386-pc/eltorito.img", "boot/grub/eltorito.img"});
    if (grub) {
        log_line("DEBUG bootloader: GRUB");
        return {"grub", *grub, "boot.catalog", *efi_image};
    }

    throw BuildError("Estrutura de boot não reconhecida.");
}

// ==========================================================
// Criação ISO Debian / Ubuntu
// ==========================================================

// Fluxo tradicional Debian/Ubuntu: remonta a ISO inteira via xorriso (mkisofs).
std::string create_debian_bootable_iso(const std::string& iso_root_in,
                                       const std::string& output_dir_in,
                                       const ProgressCallback& cb) {
    require_root();

    std::string iso_root = abspath(iso_root_in);
    std::string output_dir = abspath(output_dir_in);

    ensure_directory(output_dir);

    report_progress(cb, 98, "Gerando ISO final...");

    std::string isohdpfx = find_isohdpfx();
    BootConfig boot = detect_boot_config(iso_root);

    std::string boot_image_path = iso_root + "/" + boot.boot_image;
    std::string efi_image_path = iso_root + "/" + boot.efi_image;

    if (!is_file(boot_image_path)) throw BuildError("Imagem de boot não encontrada: " + boot_image_path);
    if (!is_file(efi_image_path)) throw BuildError("Imagem EFI não encontrada: " + efi_image_path);

    TempDir temp_dir(make_temp_dir("iso-output-", output_dir));
    std::string temp_iso = temp_dir.path + "/custom_linux.iso";
    std::string final_iso = output_dir + "/custom_linux.iso";

    if (path_exists(final_iso)) remove_path(final_iso);

    std::vector<std::string> command = {
        "xorriso", "-as", "mkisofs",
        "-r", "-V", "CustomLinux", "-J", "-l", "-iso-level", "3",
        "-isohybrid-mbr", isohdpfx,
        "-c", boot.boot_catalog,
        "-b", boot.boot_image,
        "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table",
        "-eltorito-alt-boot", "-e", boot.efi_image, "-no-emul-boot",
        "-isohybrid-gpt-basdat",
        "-o", temp_iso,
        iso_root,
    };

    log_line("DEBUG comando xorriso Debian/Ubuntu:");
    log_line(join(command, " "));

    run(command);

    if (!is_file(temp_iso)) throw BuildError("O xorriso terminou, mas a ISO não foi criada.");

    std::error_code ec;
    uintmax_t iso_size = fs::file_size(temp_iso, ec);
    if (ec || iso_size == 0) throw BuildError("A ISO criada está vazia.");

    log_line("DEBUG tamanho da ISO: " + size_mb(iso_size) + " MB");

    move_file(temp_iso, final_iso);

    log_line("ISO criada com sucesso: " + final_iso);
    report_progress(cb, 100, "ISO criada com sucesso!");
    return final_iso;
}

// ==========================================================
// Criação ISO Arch
// ==========================================================

// Cria uma ISO Arch preservando integralmente o boot da ISO original através
// do "xorriso -boot_image any replay". NÃO reconstrói MBR/GPT/El Torito/EFI
// manualmente.
std::string create_arch_bootable_iso(const std::string& original_iso_in,
                                     const std::string& iso_root_in,
                                     const std::string& squashfs_path_in,
                                     const std::string& output_dir_in,
                                     const ProgressCallback& cb) {
    require_root();

    std::string original_iso = abspath(original_iso_in);
    std::string iso_root = abspath(iso_root_in);
    std::string squashfs_path = abspath(squashfs_path_in);
    std::string output_dir = abspath(output_dir_in);

    if (!is_file(original_iso)) throw BuildError("ISO original não encontrada: " + original_iso);
    if (!is_file(squashfs_path)) throw BuildError("SquashFS personalizado não encontrado: " + squashfs_path);

    ensure_directory(output_dir);

    report_progress(cb, 99, "Reconstruindo ISO Arch preservando o boot original...");

    TempDir temp_dir(make_temp_dir("arch-iso-output-", output_dir));
    std::string temp_iso = temp_dir.path + "/custom_arch.iso";
    std::string final_iso = output_dir + "/custom_linux.iso";

    const std::string squashfs_iso_path = "/arch/x86_64/airootfs.sfs";
    std::string checksum_path = iso_root + "/arch/x86_64/airootfs.sha512";

    if (path_exists(final_iso)) remove_path(final_iso);

    std::vector<std::string> command = {
        "xorriso",
        "-indev", original_iso,
        "-outdev", temp_iso,
        "-map", squashfs_path, squashfs_iso_path,
    };

    if (is_file(checksum_path)) {
        command.insert(command.end(), {"-map", checksum_path, "/arch/x86_64/airootfs.sha512"});
    }

    command.insert(command.end(), {"-boot_image", "any", "replay", "-commit", "-end"});

    log_line("DEBUG comando xorriso Arch:");
    log_line(join(command, " "));

    run(command);

    if (!is_file(temp_iso)) throw BuildError("O xorriso terminou, mas a ISO Arch não foi criada.");

    std::error_code ec;
    uintmax_t iso_size = fs::file_size(temp_iso, ec);
    if (ec || iso_size == 0) throw BuildError("A ISO Arch criada está vazia.");

    log_line("DEBUG tamanho da ISO Arch: " + size_gb(iso_size) + " GB");

    // Validação do boot
    report_progress(cb, 99, "Validando boot da ISO Arch...");

    RunResult validation = run({"xorriso", "-indev", temp_iso,
                                "-report_el_torito", "plain",
                                "-report_system_area", "plain"},
                               false, {0}, true);

    log_line("DEBUG validação El Torito/System Area:");
    log_line(validation.output);

    if (validation.returncode != 0) {
        throw BuildError("Falha ao validar a estrutura de boot da ISO Arch.");
    }
    if (validation.output.find("El Torito") == std::string::npos) {
        throw BuildError("A ISO Arch resultante não apresenta informações El Torito.");
    }
    if (validation.output.find("UEFI") == std::string::npos) {
        throw BuildError("A ISO Arch resultante não apresenta uma entrada UEFI no El Torito.");
    }

    move_file(temp_iso, final_iso);

    log_line("ISO Arch criada com sucesso: " + final_iso);
    report_progress(cb, 100, "ISO Arch criada com sucesso!");
    return final_iso;
}

// Seleciona o método correto de criação da ISO.
std::string create_bootable_iso(const std::string& iso_root,
                                const std::string& output_dir,
                                const ProgressCallback& cb,
                                const std::string& distro,
                                const std::string& original_iso,
                                const std::string& squashfs_path) {
    if (distro == "arch") {
        if (original_iso.empty()) {
            throw BuildError("A ISO original é obrigatória para criar uma ISO Arch usando replay.");
        }
        if (squashfs_path.empty()) throw BuildError("O caminho do SquashFS é obrigatório.");
        return create_arch_bootable_iso(original_iso, iso_root, squashfs_path, output_dir, cb);
    }
    if (distro == "debian") return create_debian_bootable_iso(iso_root, output_dir, cb);

    throw BuildError("Distribuição não suportada para criação da ISO: " + distro);
}

// ==========================================================
// Limpeza
// ==========================================================

// Remove todo o conteúdo anterior do diretório de trabalho.
void clean_output_directory(const std::string& out_dir) {
    if (!is_dir(out_dir)) return;

    std::vector<std::string> entries;
    for (const auto& e : fs::directory_iterator(out_dir)) entries.push_back(e.path().string());

    for (const auto& path : entries) {
        log_line("DEBUG removendo: " + path);
        remove_path(path);
    }
}

}  // namespace

// ==========================================================
// Função principal
// ==========================================================

BuildResult build_iso(const std::string& iso_path_in,
                      const std::string& out_dir_in,
                      ProgressCallback cb,
                      const std::vector<std::string>& pkg_paths) {
    // PRIMEIRA COISA: verifica root antes de fazer qualquer trabalho.
    require_root();

    std::string iso_path = abspath(iso_path_in);
    std::string out_dir = abspath(out_dir_in);

    if (!is_file(iso_path)) throw BuildError("ISO não encontrada: " + iso_path);

    if (is_file(out_dir)) {
        throw BuildError("O caminho de saída informado é um arquivo, não um diretório.");
    }

    validate_dependencies();
    ensure_directory(out_dir);

    report_progress(cb, 5, "Preparando processo...");

    // clean_output_directory() apaga TUDO dentro de out_dir. Se a ISO de
    // entrada estiver dentro dele, ela seria apagada antes de ser extraída:
    // nesse caso trabalhamos numa cópia temporária.
    TempDir temp_input;
    if (iso_path == out_dir || iso_path.rfind(out_dir + "/", 0) == 0) {
        temp_input.path = make_temp_dir("iso-input-", out_dir);
        std::string safe_iso = temp_input.path + "/" + fs::path(iso_path).filename().string();

        std::error_code ec;
        fs::copy_file(iso_path, safe_iso, fs::copy_options::overwrite_existing, ec);
        if (ec) throw BuildError("Falha ao copiar a ISO de entrada: " + ec.message());

        log_line("WARNING: a ISO de entrada estava dentro do diretório de saída. "
                 "Copiada temporariamente para: " + safe_iso);
        iso_path = safe_iso;
    }

    log_line("DEBUG ISO original: " + iso_path);
    log_line("DEBUG diretório de trabalho: " + out_dir);

    clean_output_directory(out_dir);

    // Extração da ISO (xorriso; fallback 7z)
    report_progress(cb, 10, "Extraindo ISO...");

    try {
        extract_iso(iso_path, out_dir);
        log_line("DEBUG ISO extraída com xorriso (osirrox).");
    } catch (const std::exception& e) {
        log_line(std::string("WARNING: falha ao extrair com xorriso (") + e.what() +
                 "); tentando 7z como alternativa...");
        clean_output_directory(out_dir);
        extract_with_7z(iso_path, out_dir);
        log_line("DEBUG ISO extraída com 7z (fallback).");
    }

    // Detecção da distribuição
    std::string distro = detect_distro(out_dir);
    log_line("DEBUG distribuição detectada no build: " + distro);

    std::optional<CustomizeResult> result;

    // Personalização
    if (!pkg_paths.empty()) {
        result = customize_live_system(out_dir, pkg_paths, cb);

        rebuild_squashfs(result->squashfs_path, result->work_dir, cb, result->squashfs_compression);

        if (distro == "arch") {
            update_arch_squashfs_checksum(out_dir, result->squashfs_path);
            remove_arch_backup_files(out_dir);
        }

        if (path_exists(result->work_dir)) remove_path(result->work_dir);
    } else if (distro == "arch") {
        remove_arch_backup_files(out_dir);
    }

    // Criação da ISO
    std::string final_iso;

    if (distro == "arch") {
        if (!result) {
            report_progress(cb, 99, "Nenhuma personalização solicitada. Copiando ISO Arch original...");

            final_iso = out_dir + "/custom_linux.iso";
            if (path_exists(final_iso)) remove_path(final_iso);

            std::error_code ec;
            fs::copy_file(iso_path, final_iso, fs::copy_options::overwrite_existing, ec);
            if (ec) throw BuildError("Falha ao copiar a ISO: " + ec.message());

            report_progress(cb, 100, "ISO criada com sucesso!");
        } else {
            final_iso = create_bootable_iso(out_dir, out_dir, cb, "arch", iso_path, result->squashfs_path);
        }
    } else {
        final_iso = create_bootable_iso(out_dir, out_dir, cb, "debian", iso_path,
                                        result ? result->squashfs_path : std::string());
    }

    report_progress(cb, 100, "Finalizado!");

    return {"iso", "ok", final_iso, distro};
}

}  // namespace isob
