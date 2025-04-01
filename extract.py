import re
import logging
from pathlib import Path

class HashExtractor:
    def __init__(self):
        self.setup_logging()
        self.input_file = "hashes"
        self.output_file = "clean_hashes.txt"
        self.hash_pattern = re.compile(r'^[A-Za-z0-9$]+:[0-9]+:[a-f0-9]+:[a-f0-9]+')
        self.ansi_pattern = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
        self.process_hashes()
    
    def setup_logging(self):
        """Set up logging to file and console."""
        log_dir = Path("exploit_output")
        log_file = log_dir / "exploit_log.log"
        log_dir.mkdir(exist_ok=True)

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - INFO - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def process_hashes(self):
        """Extracts valid hashes from input file and writes them to output file."""
        try:
            with open(self.input_file, 'r', encoding='utf-8') as infile:
                hash_lines = [self.ansi_pattern.sub('', line).strip() for line in infile if self.hash_pattern.match(line)]

            with open(self.output_file, 'w', encoding='utf-8') as outfile:
                outfile.write('\n'.join(hash_lines) + '\n')

            self.logger.info("[*] Hash extraction completed successfully.")
        except FileNotFoundError:
            self.logger.error(f"Error: {self.input_file} not found.")
        except Exception as e:
            self.logger.error(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    HashExtractor()
