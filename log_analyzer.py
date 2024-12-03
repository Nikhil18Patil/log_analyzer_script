import re
import csv
from collections import defaultdict, Counter

def parse_log_file(file_path):
    """Reads the log file and returns a list of log lines."""
    try:
        with open(file_path, 'r') as file:
            return file.readlines()
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return []
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return []

def count_requests_per_ip(log_lines):
    """Counts the number of requests made by each IP address."""
    ip_counts = Counter()
    for line in log_lines:
        match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            ip_counts[match.group(1)] += 1
    return ip_counts

def find_most_accessed_endpoint(log_lines):
    """Finds the most frequently accessed endpoint from the log file."""
    endpoint_counts = Counter()
    for line in log_lines:
        match = re.search(r'\"(?:GET|POST|PUT|DELETE) (/\S*) HTTP/', line)
        if match:
            endpoint_counts[match.group(1)] += 1
    if endpoint_counts:
        return endpoint_counts.most_common(1)[0]
    return None, 0

def detect_suspicious_activity(log_lines, threshold=10):
    """Detects IP addresses with failed login attempts exceeding a threshold."""
    failed_login_attempts = defaultdict(int)
    for line in log_lines:
        if '401' in line or 'Invalid credentials' in line:
            match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
            if match:
                failed_login_attempts[match.group(1)] += 1
    
    # Filter IPs exceeding the threshold
    suspicious_ips = {ip: count for ip, count in failed_login_attempts.items() if count > threshold}
    return suspicious_ips

def save_results_to_csv(ip_counts, most_accessed_endpoint, suspicious_ips, output_file='log_analysis_results.csv'):
    """Saves the analysis results to a CSV file."""
    try:
        with open(output_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            
            # Write Requests per IP
            writer.writerow(["IP Address", "Request Count"])
            for ip, count in ip_counts.items():
                writer.writerow([ip, count])
            writer.writerow([])

            # Write Most Accessed Endpoint
            writer.writerow(["Most Accessed Endpoint", "Access Count"])
            writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
            writer.writerow([])

            # Write Suspicious Activity
            writer.writerow(["Suspicious IP Address", "Failed Login Attempts"])
            for ip, count in suspicious_ips.items():
                writer.writerow([ip, count])
    except Exception as e:
        print(f"Error writing to CSV file: {e}")

def main():
    log_file_path = 'sample.log'  # Update this path if needed
    log_lines = parse_log_file(log_file_path)
    
    if not log_lines:
        print("No log data to process.")
        return
    
    # Process log data
    ip_counts = count_requests_per_ip(log_lines)
    most_accessed_endpoint = find_most_accessed_endpoint(log_lines)
    suspicious_ips = detect_suspicious_activity(log_lines)

    # Display results
    print("\nIP Address Request Counts:")
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    if most_accessed_endpoint:
        print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

    # Save results to CSV
    save_results_to_csv(ip_counts, most_accessed_endpoint, suspicious_ips)
    print("\nAnalysis results saved to 'log_analysis_results.csv'.")

if __name__ == "__main__":
    main()
