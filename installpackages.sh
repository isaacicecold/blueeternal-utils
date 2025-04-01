#!/bin/bash

# Function to check for internet connectivity
check_internet() {
    echo "[*] Checking internet connectivity..."
    if ! ping -c 1 google.com &> /dev/null; then
        echo "[!] No internet connection. Please check your network settings."
        exit 1
    fi
    echo "[*] Internet connectivity verified."
}

# Function to check if snap is installed
check_snap_installed() {
    if ! command -v snap &> /dev/null; then
        echo "[*] Snap not found. Installing Snap..."
        sudo apt-get update
        sudo apt install -y snapd
        sudo systemctl enable --now snapd.socket
    else
        echo "[*] Snap is already installed."
    fi
}

# Install Metasploit Framework and John the Ripper via snap and apt
install_tools() {
    echo "[*] Installing Metasploit Framework..."
    sudo snap install metasploit-framework -y 
    
    echo "[*] Installing John the Ripper..."
    sudo apt install john
}

# Main function to run the setup
main() {
    check_internet  # Check internet connection before proceeding
    sudo apt-get update  # Update package list for apt
    check_snap_installed  # Check and install snap if necessary
    install_tools  # Install Metasploit Framework and John the Ripper
    echo "[*] Installation complete. Both Metasploit and John the Ripper are installed."
}

# Run the main function
main
