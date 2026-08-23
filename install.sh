#!/bin/bash
# AeroGuard WIDS - Automated Linux Installer

# Ensure the script is run with root privileges
if [ "$EUID" -ne 0 ]; then
  echo -e "\e[31m[!] Please run this installer as root (sudo ./install.sh)\e[0m"
  exit 1
fi

echo -e "\e[34m"
echo "    ___                     ______                     __"
echo "   /   |  ___  _________   / ____/_  ______ __________/ /"
echo "  / /| | / _ \/ ___/ __ \ / / __/ / / / __ \`/ ___/ __  / "
echo " / ___ |/  __/ /  / /_/ // /_/ / /_/ / /_/ / /  / /_/ /  "
echo "/_/  |_|\___/_/   \____/ \____/\__,_/\__,_/_/   \__,_/   "
echo "                                                         "
echo -e "\e[0m"
echo -e "\e[32m[*] Starting AeroGuard Automated Installer...\e[0m"

echo -e "\e[33m[*] Step 1: Installing system dependencies (apt)...\e[0m"
apt-get update -y
apt-get install -y python3 python3-pip python3-venv iw tcpdump aircrack-ng

echo -e "\e[33m[*] Step 2: Creating Python Virtual Environment...\e[0m"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "\e[32m[+] Virtual environment created.\e[0m"
else
    echo -e "\e[32m[+] Virtual environment already exists. Skipping.\e[0m"
fi

echo -e "\e[33m[*] Step 3: Installing Python dependencies...\e[0m"
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

# Ensure the run script is executable
if [ -f "run.sh" ]; then
    chmod +x run.sh
fi

echo -e "\e[32m============================================================\e[0m"
echo -e "\e[32m[+] AeroGuard installation completed successfully!\e[0m"
echo -e "\e[32m============================================================\e[0m"
echo ""
echo -e "To start AeroGuard, run the following command:"
echo -e "\e[36m    sudo ./run.sh\e[0m"
echo ""
echo -e "Make sure your WiFi adapter is plugged in!"
