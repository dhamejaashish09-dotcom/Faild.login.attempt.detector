import csv
from collections import Counter
from pathlib import Path

# Configuration
LOG_FILE = Path(__file__).parent / "login_logs.csv"
THRESHOLD = 3


def detect_failed_logins():
    failed_attempts = Counter()

    # Check whether the log file exists
    if not LOG_FILE.exists():
        print("Error: login_logs.csv file not found!")
        return

    # Read login logs
    with open(LOG_FILE, "r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)

        # Validate CSV columns
        if not reader.fieldnames or not {
            "ip_address", "status"
        }.issubset(reader.fieldnames):
            print("Error: CSV columns are incorrect!")
            print("Required columns: timestamp,ip_address,status")
            return

        total_records = 0

        for row in reader:
            total_records += 1

            ip = row["ip_address"].strip()
            status = row["status"].strip().upper()

            if status == "FAILED":
                failed_attempts[ip] += 1

    # Display results
    print("\n" + "=" * 45)
    print("      FAILED LOGIN DETECTION SYSTEM")
    print("=" * 45)

    print(f"Total login records: {total_records}")
    print(f"Alert threshold: {THRESHOLD} failed attempts")

    if not failed_attempts:
        print("\nNo failed login attempts found.")

    for ip, count in failed_attempts.most_common():
        print(f"\nIP Address: {ip}")
        print(f"Failed Attempts: {count}")

        if count >= THRESHOLD:
            print("Status: ALERT")
            print("Reason: Multiple failed login attempts detected!")
        else:
            print("Status: NORMAL")

    print("\n" + "=" * 45)
    print("Analysis completed.")
    print("=" * 45)


if __name__ == "__main__":
    detect_failed_logins()