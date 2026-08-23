#!/bin/bash
# AeroGuard WIDS - Quick Start Script

if [ "$EUID" -ne 0 ]; then
  echo -e "\e[31m[!] Please run AeroGuard as root (sudo ./run.sh)\e[0m"
  echo "Raw packet sniffing and injection requires root privileges."
  exit 1
fi

if [ ! -d "venv" ]; then
  echo -e "\e[31m[!] Virtual environment not found!\e[0m"
  echo "Please run 'sudo ./install.sh' first."
  exit 1
fi

echo -e "\e[32m[*] Starting AeroGuard WIDS Backend...\e[0m"
echo -e "\e[36m    Dashboard will be available at: http://localhost:8000\e[0m"
echo ""

# Start the application using the python binary from the virtual environment
./venv/bin/python -m backend.app
