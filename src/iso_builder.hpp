// ISO Builder — núcleo em C++17 (porta do iso_linux.py)
//
// Extrai uma ISO Linux, personaliza o sistema Live via chroot (instalando
// pacotes .deb ou Arch) e recria a imagem bootável (BIOS + UEFI).
//
// Suporta:
//   - Debian/Ubuntu e derivados (casper/ ou live/filesystem.squashfs)
//   - Arch Linux (arch/x86_64/airootfs.sfs)
//
// IMPORTANTE: o processo inteiro precisa rodar como root (chroot e mounts).
// Nenhuma função aqui usa sudo internamente.
#pragma once

#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace isob {

// Erro genérico de build (equivalente ao RuntimeError/PermissionError do Python).
class BuildError : public std::runtime_error {
public:
    explicit BuildError(const std::string& msg) : std::runtime_error(msg) {}
};

// Callback de progresso: (porcentagem 0-100, mensagem de status).
using ProgressCallback = std::function<void(int, const std::string&)>;

struct BuildResult {
    std::string method;   // "iso"
    std::string status;   // "ok"
    std::string path;     // caminho da ISO final
    std::string distro;   // "debian" ou "arch"
};

// Executa o processo completo de criação da ISO.
//   iso_path  : ISO original
//   out_dir   : diretório de trabalho/saída (TODO o conteúdo anterior é apagado!)
//   cb        : callback de progresso (opcional)
//   pkg_paths : pacotes a instalar (.deb ou .pkg.tar.zst); vazio = só remonta
BuildResult build_iso(const std::string& iso_path,
                      const std::string& out_dir,
                      ProgressCallback cb = nullptr,
                      const std::vector<std::string>& pkg_paths = {});

// Escreve uma linha no log (stdout) de forma thread-safe.
void log_line(const std::string& line);

}  // namespace isob
