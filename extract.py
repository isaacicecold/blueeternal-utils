#!/usr/bin/env python3
import re

# Define input and output file paths
input_file = "/home/alaja1/hashes"
output_file = "/home/alaja1/clean_hashes.txt"

# Regex to match hashdump lines (username:RID:hex:hex:optional-colons)
hash_pattern = re.compile(r'^[A-Za-z0-9$]+:[0-9]+:[a-f0-9]+:[a-f0-9]+')

# Regex to remove ANSI escape codes
ansi_pattern = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')

try:
    with open(input_file, 'r', encoding='utf-8') as infile:
        print("Lines read from file:")
        hash_lines = []
        for line in infile:
            # Remove ANSI escape codes first
            clean_line = ansi_pattern.sub('', line).rstrip()
            print(f"Checking: '{clean_line}'")
            if hash_pattern.match(clean_line):
                print(f"Matched: '{clean_line}'")
                hash_lines.append(clean_line)

    # Write the filtered lines to the output file
    with open(output_file, 'w', encoding='utf-8') as outfile:
        outfile.write('\n'.join(hash_lines) + '\n')

    print(f"\nHashes extracted to {output_file}")
    with open(output_file, 'r', encoding='utf-8') as outfile:
        print(outfile.read())

except FileNotFoundError:
    print(f"Error: {input_file} not found.")
except Exception as e:
    print(f"An error occurred: {e}")
