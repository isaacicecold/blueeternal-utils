import re
import logging
from pathlib import Path

class HashExtractor:
    def __init__(self, input_file="hashes", output_file="clean_hashes.txt"):
        self.input_file = input_file
        self.output_file = output_file
        self.setup_logging()

    def setup_logging(self):
        """Set up logging to both file and console."""
        log_dir = Path("exploit_output")
        log_file = log_dir / "exploit_log.log"
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

    def extract_hashes(self):
        """Extract valid hashes from input file and save to output file."""
        hash_pattern = re.compile(r'^[A-Za-z0-9$]+:[0-9]+:[a-f0-9]+:[a-f0-9]+')
        ansi_pattern = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')

        try:
            with open(self.input_file, 'r', encoding='utf-8') as infile:
                self.logger.info("[*] Reading input file...")
                hash_lines = []
                for line in infile:
                    clean_line = ansi_pattern.sub('', line).rstrip()
                    if hash_pattern.match(clean_line):
                        hash_lines.append(clean_line)
                        self.logger.info(f"[+] Matched: {clean_line}")

            with open(self.output_file, 'w', encoding='utf-8') as outfile:
                outfile.write('\n'.join(hash_lines) + '\n')
            
            self.logger.info(f"[*] Hashes extracted to {self.output_file}")
            self.logger.info("[*] Exploitation process completed.")

        except FileNotFoundError:
            self.logger.error(f"Error: {self.input_file} not found.")
        except Exception as e:
            self.logger.error(f"An error occurred: {e}")

if __name__ == "__main__":
    extractor = HashExtractor()
    extractor.extract_hashes()
