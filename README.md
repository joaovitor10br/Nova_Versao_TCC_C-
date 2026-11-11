# ISO Builder — versão C++ (backend)

Versão experimental do backend do TCC **ISO Builder**, reescrita em **C++17**.
O frontend (`frontend/`) é o mesmo da versão Python, sem nenhuma alteração.
O projeto original (Flask) não é tocado por esta versão.

## Requisitos

```bash
sudo apt install build-essential xorriso squashfs-tools p7zip-full isolinux
```
(No Arch: `sudo pacman -S base-devel libisoburn squashfs-tools p7zip syslinux`; no Fedora: `sudo dnf install gcc-c++ make xorriso squashfs-tools p7zip syslinux`.)

## Compilar e executar

```bash
make
sudo ./iso-builder            # http://127.0.0.1:5000
```

Opções: `--port N`, `--frontend DIR`, `--base-dir DIR` (padrão: `~/iso_builder` do usuário que chamou o sudo).
O processo precisa rodar como **root** (chroot e mounts).

## Estrutura

| Arquivo | Função |
|---|---|
| `src/main.cpp` | Servidor HTTP (rotas `/`, `/progress/<id>`, `POST /build/linux`) |
| `src/iso_builder.cpp/.hpp` | Porta de `iso_linux.py` (extração, chroot, squashfs, ISO) |
| `src/sha512.hpp` | SHA-512 próprio (checksum do `airootfs.sha512` do Arch) |
| `third_party/httplib.h` | cpp-httplib v0.18.3 (licença MIT) |

## Diferenças em relação à versão Python

- Comandos externos são executados com `posix_spawnp` (sem shell).
- Upload em *streaming*: ISOs de vários GB não ficam na RAM.
- `try/finally` do Python virou exceções + desmontagem garantida antes de relançar o erro.
- Escuta apenas em `127.0.0.1`.
- Proteção extra: a pasta de saída não pode ser pasta pessoal, ancestrais dela, `/etc`, `/usr` etc. (**o build apaga o conteúdo da pasta de saída**).
- `mount_loop_linux_and_copy` não foi portada (não é usada pelo fluxo atual).

## O que foi testado

Em ambiente de testes (container, root), com ISOs **sintéticas** (mini rootfs com `dpkg`/`apt-get`/`pacman` falsos):

- Rotas estáticas, 404 de tarefa, erros 400 de validação, nome de arquivo malicioso (`../../x.iso`) sanitizado.
- Fluxo Debian/Ubuntu: extração, chroot, instalação, squashfs, ISO com BIOS + UEFI.
- Fluxo Arch: o erro *"could not determine root mount point /"* é reproduzido pelo pacman falso e resolvido pelo bind mount; `airootfs.sha512` atualizado; El Torito BIOS + UEFI validado.
- Falha do `apt-get`: o erro é reportado e nenhum mount fica pendurado.
- SHA-512 idêntico ao `sha512sum`.

**Não testado:** boot de uma ISO real gerada por esta versão (QEMU/VirtualBox) nem pacotes reais. Faça esse teste na sua VM antes de confiar nela.
