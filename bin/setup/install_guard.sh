#!/bin/bash

# Terminal color codes
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
CYAN=$(tput setaf 6)
BOLD=$(tput bold)
RESET=$(tput sgr0)

OS=$(uname -s)

case "$OS" in
    Linux)
        echo "${GREEN}${BOLD}🛡️  Vaulthalla recognizes this as a worthy environment.${RESET}"
        ;;
    Darwin)
        # macOS: `make dev` installs the isolated dev instance from source (bin/lib/platform.sh). A production install
        # comes from the installer package or the Homebrew cask, never from these scripts.
        if [ "${VH_BUILD_MODE:-}" = dev ]; then
            echo "${GREEN}${BOLD}🛡️  macOS: installing the isolated dev instance (sh.vaulthalla.dev.*, vh-dev).${RESET}"
        else
            cat << EOF
${YELLOW}${BOLD}⛔️  macOS: production installs come from the package${RESET}

${CYAN}Install Vaulthalla on a Mac with the signed installer package or Homebrew:
    brew install --cask valkyrianlabs/tap/vaulthalla-server   (headless; vaulthalla adds the Desktop app)
    or open vaulthalla-<version>-arm64.pkg

From a source checkout, 'make dev' installs an isolated development instance
(vh-dev, sh.vaulthalla.dev.*) that never touches a production install.${RESET}
EOF
            exit 1
        fi
        ;;
    MINGW* | MSYS* | CYGWIN* | Windows_NT)
        clear
        cat << EOF
${RED}${BOLD}🚨🚨🚨  WINDOWS DETECTED — IMMEDIATE INTERVENTION REQUIRED  🚨🚨🚨${RESET}

${RED}╔══════════════════════════════════════════════════════════════════════╗
║  🪟  Windows Users                                                     ║
║                                                                       ║
║  You run Windows? Cool.                                               ║
║                                                                       ║
║  If you want to run Vaulthalla:                                       ║
║    - Install a Linux VM.                                              ║
║    - Or boot from USB like a grown adult.                             ║
║    - Or SSH into a real server like the rest of us.                   ║
║                                                                       ║
║  Whatever crimes your hypervisor commits to bridge FUSE with NTFS—    ║
║  it's not our problem.                                                ║
║                                                                       ║
║  We don’t patch for Windows.                                          ║
║  We don’t test on Windows.                                            ║
║  And we certainly don’t apologize for it.                             ║
╚══════════════════════════════════════════════════════════════════════╝${RESET}

${YELLOW}This isn’t personal. It’s architectural. Return with a real OS.${RESET}
EOF
        sleep 3
        exit 1
        ;;
    *)
        echo "${YELLOW}${BOLD}🧐 Unknown OS: $OS${RESET}"
        echo "${CYAN}Proceeding... but understand this is unsupported terrain.${RESET}"
        ;;
esac
