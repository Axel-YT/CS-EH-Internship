"""
=====================================================
        PENETRATION TESTING TOOLKIT (EDUCATIONAL)
=====================================================

This tool demonstrates basic penetration testing concepts:
1. Port Scanning
2. HTTP Header Security Analysis

NOTE:
- This tool is for LEARNING PURPOSES ONLY.
- Scan only websites or servers you own or have permission to test.
"""

import socket
import requests

# --------------------------------------------------
# FUNCTION 1: PORT SCANNER
# --------------------------------------------------
def port_scanner(target, start_port, end_port):
    """
    Scans a range of ports on the target system
    and reports which ports are open.
    """

    print("\n[+] Starting Port Scan...")
    print(f"Target: {target}")
    print(f"Port Range: {start_port} - {end_port}\n")

    open_ports = []

    for port in range(start_port, end_port + 1):
        try:
            # Create a socket object
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Set timeout to avoid long waiting
            sock.settimeout(0.5)

            # Try connecting to the target
            result = sock.connect_ex((target, port))

            # If result is 0, port is open
            if result == 0:
                print(f"[OPEN] Port {port}")
                open_ports.append(port)

            sock.close()

        except Exception as e:
            print(f"Error scanning port {port}: {e}")

    if not open_ports:
        print("\nNo open ports found.")
    else:
        print("\nOpen ports:", open_ports)


# --------------------------------------------------
# FUNCTION 2: HTTP SECURITY HEADER CHECK
# --------------------------------------------------
def check_http_headers(url):
    """
    Checks important HTTP security headers
    that protect against common attacks.
    """

    print("\n[+] Checking HTTP Security Headers...")

    try:
        response = requests.get(url, timeout=5)

        headers = response.headers

        # Common important security headers
        security_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "Referrer-Policy"
        ]

        for header in security_headers:
            if header in headers:
                print(f"[✓] {header}: PRESENT")
            else:
                print(f"[!] {header}: MISSING")

    except requests.exceptions.RequestException:
        print("[-] Failed to connect to the target.")


# --------------------------------------------------
# MAIN MENU FUNCTION
# --------------------------------------------------
def main():
    print("==============================================")
    print("        PENETRATION TESTING TOOLKIT")
    print("==============================================")
    print("1. Port Scanner")
    print("2. HTTP Security Header Checker")
    print("3. Exit")

    choice = input("\nEnter your choice (1/2/3): ").strip()

    if choice == "1":
        target = input("Enter target IP or domain (example: scanme.nmap.org): ")
        start_port = int(input("Enter start port: "))
        end_port = int(input("Enter end port: "))
        port_scanner(target, start_port, end_port)

    elif choice == "2":
        url = input("Enter website URL (http:// or https://): ")
        check_http_headers(url)

    elif choice == "3":
        print("Exiting... Stay ethical 👍")

    else:
        print("Invalid choice. Try again.")


# --------------------------------------------------
# PROGRAM ENTRY POINT
# --------------------------------------------------
if __name__ == "__main__":
    main()
