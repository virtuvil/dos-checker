import sys
import re
from collections import defaultdict

def detect_dos_attacks(log_file_path):
    # Regular expression pattern to match Apache log entries
    apache_log_pattern = r'^(\S+) \S+ \S+ \[([^:]+):(\d+:\d+:\d+) .*\] "(\S+) (.+?) (\S+)" (\d+) (\d+)'

    # Dictionary to store IP addresses and request counts
    ip_counts = defaultdict(int)

    # Read the log file
    with open(log_file_path, 'r') as file:
        for line in file:
            match = re.match(apache_log_pattern, line)
            if match:
                ip_address = match.group(1)
                request_method = match.group(4)
                if request_method == 'GET' or request_method == 'POST':
                    ip_counts[ip_address] += 1

    # Check for potential DoS attacks
    for ip, count in ip_counts.items():
        if count > 1000:  # Adjust the threshold as needed
            print(f"Potential DoS attack detected from {ip}. Requests: {count}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python detect_dos_attacks.py <apache_access_log>")
        sys.exit(1)

    log_file_path = sys.argv[1]
    detect_dos_attacks(log_file_path)

