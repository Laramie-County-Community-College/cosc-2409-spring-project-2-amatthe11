import re
import os


def extract_log_data(line):
    """Extracts timestamp, IP address, URL, and status code from a valid log line."""
    match = re.search(
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - "
        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - "
        r"\"GET (.+) HTTP/1.1\" (\d+)", line
    )
    if match:
        timestamp, ip, url, status_code = match.groups()
        return timestamp, ip, url, status_code
    else:
        return None, None, None, None

def analyze_log_file(filename="access.log"):
    """Analyzes the log file and prints summary statistics."""
    try:
        with open(filename, "r") as f:
            log_lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: Log file '{filename}' not found.")
        return
    
    error_count = 0
    unique_ips = set()
    url_counts = {}

    for line in log_lines:
        timestamp, ip, url, status_code = extract_log_data(line)

        if ip and url and status_code:
            unique_ips.add(ip)
            url_counts[url] = url_counts.get(url, 0) + 1

            if int(status_code) >= 400:
                error_count += 1

    # Print output
    print(f"Total Errors (4xx and 5xx): {error_count}")
    print(f"Unique IP Addresses: {len(unique_ips)}")
    print("URL Access Counts:")
    for url, count in sorted(url_counts.items()):
        print(f"  {url}: {count}")

# Only run this if you directly run log_analyzer.py
if __name__ == "__main__":
    analyze_log_file()



