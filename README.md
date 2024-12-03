# Log Analyzer Tool

### Overview
This Python script processes web server log files to extract and analyze key information. It evaluates log data to provide insights such as request counts per IP address, the most frequently accessed endpoints, and potential suspicious activities like brute-force login attempts. This tool is particularly useful for cybersecurity-related tasks, network administration, and log auditing.

---

### Key Features
1. **Count Requests per IP Address**:
   - Parses the log file to count how many requests each IP address made.
   - Displays the results in descending order of request count.

2. **Identify the Most Frequently Accessed Endpoint**:
   - Extracts all endpoint requests (e.g., URLs or resource paths).
   - Determines the endpoint accessed the most frequently.

3. **Detect Suspicious Activity**:
   - Identifies IP addresses with excessive failed login attempts.
   - Uses a configurable threshold (default: 10 attempts) to flag potential brute-force attacks.

4. **Generate a CSV Report**:
   - Saves the analysis results in a structured CSV file named `log_analysis_results.csv`.
   - Contains sections for IP request counts, the most accessed endpoint, and flagged suspicious activity.

---

### Dependencies
Ensure you have Python 3.6 or higher installed. The script uses standard libraries (`re`, `csv`, `collections`) and requires no additional packages.

---

### Installation
1. **Clone the Repository or Download the Script:**
   ```bash
   git clone https://github.com/yourusername/log-analyzer.git
   cd log-analyzer
