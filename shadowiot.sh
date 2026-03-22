#!/usr/bin/env bash
# ShadowIoT - Red Team Network Mapper

BOLD="\033[1m"
RED="\033[1;31m"
GREEN="\033[1;32m"
BLUE="\033[1;34m"
RESET="\033[0m"

banner() {
  clear
  echo -e "${RED}${BOLD}"
  cat <<'EOF'
 ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗██╗ ██████╗ ████████╗
 ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██║██╔════╝ ╚══██╔══╝
 ███████╗███████║███████║██████╔╝██║   ██║██║ █╗ ██║██║██║  ███╗   ██║   
 ╚════██║██╔══██║██╔══██║██╔══██╗██║   ██║██║███╗██║██║██║   ██║   ██║   
 ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██║╚██████╔╝   ██║   
 ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝ ╚═════╝    ╚═╝   
EOF
  echo -e "${RESET}"
  echo -e "${BOLD}${BLUE}                    ShadowIoT :: Adversarial Network Mapper${RESET}\n"
}

require_python() {
  if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${RED}[!] python3 not found. Please install Python 3 before continuing.${RESET}"
    exit 1
  fi
}

prompt_target() {
  local target
  read -rp "${BOLD}Enter Target IP/Range (e.g., 192.168.1.0/24): ${RESET}" target
  echo "$target"
}

run_scanner() {
  local mode="$1"
  local target="$2"
  require_python
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  local py="${script_dir}/.venv/bin/python"
  if [[ ! -x "$py" ]]; then
    py="python3"
  fi
  "$py" "${script_dir}/scanner.py" --mode "$mode" --target "$target"
}

main_menu() {
  while true; do
    banner
    echo -e "${BOLD}[1]${RESET} Scan Network (mDNS/UPnP)"
    echo -e "${BOLD}[2]${RESET} Identify Vulnerable Printers"
    echo -e "${BOLD}[3]${RESET} Credential Audit (Check Default Passwords)"
    echo -e "${BOLD}[4]${RESET} Export Network Map (JSON)"
    echo -e "${BOLD}[0]${RESET} Exit"
    echo
    read -rp "${BOLD}Select an option: ${RESET}" choice
    case "$choice" in
      1)
        target=$(prompt_target)
        run_scanner "mdns-upnp" "$target"
        read -rp "${BLUE}Press enter to return to the menu...${RESET}"
        ;;
      2)
        target=$(prompt_target)
        run_scanner "printers" "$target"
        read -rp "${BLUE}Press enter to return to the menu...${RESET}"
        ;;
      3)
        target=$(prompt_target)
        run_scanner "creds" "$target"
        read -rp "${BLUE}Press enter to return to the menu...${RESET}"
        ;;
      4)
        target=$(prompt_target)
        run_scanner "export" "$target"
        read -rp "${BLUE}Press enter to return to the menu...${RESET}"
        ;;
      0)
        echo -e "${GREEN}[+] Stay stealthy. Exiting.${RESET}"
        exit 0
        ;;
      *)
        echo -e "${RED}[!] Invalid selection. Try again.${RESET}"
        sleep 1
        ;;
    esac
  done
}

main_menu
