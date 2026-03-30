"""
Author: Jorge Echavarria
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")

# This dictionary stores common port numbers and their service names.
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}


class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property and @target.setter helps protect the target value.
    # Instead of changing it directly, the program can check if the new value is valid first.
    # In this case, it stops the target from being set to an empty string.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value != "":
            self.__target = value
        else:
            print("Error: Target cannot be empty")

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner reuses code from NetworkTool by inheriting the target attribute and its getter and setter.
# For example, it uses super().__init__(target) instead of writing the same code again.
# This helps avoid repeating code.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        sock = None

        # Q4: What would happen without try-except here?
        # Without try-except, the program could crash if a socket error happens while scanning a port.
        # That means one error could stop the whole scan.
        # Using try-except helps the program continue running.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))

            if result == 0:
                status = "Open"
            else:
                status = "Closed"

            service_name = common_ports.get(port, "Unknown")

            self.lock.acquire()
            try:
                self.scan_results.append((port, status, service_name))
            finally:
                self.lock.release()

        except socket.error as e:
            print(f"Error scanning port {port}: {e}")

        finally:
            if sock:
                sock.close()

    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # We use threading because it makes the scan faster by checking many ports at the same time.
    # If the program scanned 1024 ports one by one, it would take much longer.
    # Threads make the scanner more efficient.
    def scan_range(self, start_port, end_port):
        threads = []

        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()


def save_results(target, results):
    conn = None
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                scan_date TEXT
            )
        """)

        for port, status, service in results:
            cursor.execute("""
                INSERT INTO scans (target, port, status, service, scan_date)
                VALUES (?, ?, ?, ?, ?)
            """, (target, port, status, service, str(datetime.datetime.now())))

        conn.commit()

    except sqlite3.Error as e:
        print(f"Database error: {e}")

    finally:
        if conn:
            conn.close()


def load_past_scans():
    conn = None
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT target, port, status, service, scan_date FROM scans")
        rows = cursor.fetchall()

        if not rows:
            print("No past scans found.")
        else:
            for target, port, status, service, scan_date in rows:
                print(f"[{scan_date}] {target} : Port {port} ({service}) - {status}")

    except sqlite3.Error:
        print("No past scans found.")

    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    target_input = input("Enter target IP address (press Enter for 127.0.0.1): ").strip()

    if target_input == "":
        target_ip = "127.0.0.1"
    else:
        if target_input != "127.0.0.1":
            print("For this assignment, only 127.0.0.1 is allowed. Using 127.0.0.1 instead.")
            target_ip = "127.0.0.1"
        else:
            target_ip = target_input

    while True:
        try:
            start_port = int(input("Enter starting port number (1-1024): "))
            if start_port < 1 or start_port > 1024:
                print("Port must be between 1 and 1024.")
                continue
            break
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    while True:
        try:
            end_port = int(input("Enter ending port number (1-1024): "))
            if end_port < 1 or end_port > 1024:
                print("Port must be between 1 and 1024.")
                continue
            if end_port < start_port:
                print("End port must be greater than or equal to start port.")
                continue
            break
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    scanner = PortScanner(target_ip)
    print(f"Scanning {target_ip} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)

    open_ports = scanner.get_open_ports()

    print(f"--- Scan Results for {target_ip} ---")
    for port, status, service in open_ports:
        print(f"Port {port}: {status} ({service})")
    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    save_results(target_ip, scanner.scan_results)

    history_choice = input("Would you like to see past scan history? (yes/no): ").strip().lower()
    if history_choice == "yes":
        load_past_scans()


# Q5: New Feature Proposal
# One feature I would add is a filter to show only certain services, like HTTP or SSH.
# This could use a list comprehension to return only the ports that match the service selected by the user.
# Diagram: See diagram_101507702.png in the repository root