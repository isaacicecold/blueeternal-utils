log_error() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR - [*] $1"
}

log_info() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - [*] $1"
}

check_internet() {
    log_info "Checking internet connectivity..."
    if ! ping -c 1 google.com &> /dev/null; then
        log_error "No internet connection. Please check your network settings."
        exit 1
    fi
    log_info "Internet connectivity verified."
}

# Function to check if snap is installed
check_snap_installed() {
    if ! command -v snap &> /dev/null; then
        log_info "Snap not found. Installing Snap..."
        sudo apt-get update > /dev/null 2>&1
        sudo apt install snapd -y > /dev/null 2>&1
        sudo systemctl enable --now snapd.socket > /dev/null 2>&1
        log_info "Snap installed."
    else
        log_info "Snap is already installed."
    fi
}

# Install Metasploit Framework and John the Ripper via snap
install_tools() {
    log_info "Installing Metasploit Framework..."
    if ! snap list metasploit-framework > /dev/null 2>&1; then
        sudo snap install metasploit-framework > /dev/null 2>&1
        log_info "Metasploit Framework installed."
    else
        log_info "Metasploit Framework is already installed."
    fi

    log_info "Installing John the Ripper..."
    if ! snap list john-the-ripper > /dev/null 2>&1; then
        sudo snap install john-the-ripper > /dev/null 2>&1
        log_info "John the Ripper installed."
    else
        log_info "John the Ripper is already installed."
    fi
}

# Main function to run the setup
main() {
    check_internet  # Check internet connection before proceeding
    sudo apt-get update > /dev/null 2>&1  # Update package list silently
    check_snap_installed  # Check and install snap if necessary
    install_tools  # Install Metasploit Framework and John the Ripper
    log_info "Installation complete. Both Metasploit and John the Ripper are installed."
}

# Run the main function
main
