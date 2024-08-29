import os
from scapy.all import ICMP, IP, sr1, TCP
from ipaddress import ip_network
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import re

print_lock = Lock()

# Ping Sweep
def ping(host):
    try:
        response = sr1(IP(dst=str(host))/ICMP(), timeout=1, verbose=0)
        if response is not None:
            return str(host)
        return None
    except Exception as e:
        with print_lock:
            print(f"Error pinging {host}: {e}")
        return None

def ping_sweep(network, netmask):
    print(f"Starting Ping Sweep on {network}/{netmask}")
    live_hosts = []

    try:
        num_threads = os.cpu_count()
        hosts = list(ip_network(f"{network}/{netmask}").hosts())
        total_hosts = len(hosts)
        
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = {executor.submit(ping, host): host for host in hosts}
            for i, future in enumerate(as_completed(futures), start=1):
                host = futures[future]
                result = future.result()
                with print_lock:
                    print(f"Scanning: {i}/{total_hosts}", end="\r")
                    if result is not None:
                        print(f"\nHost {host} is online.")
                        live_hosts.append(result)

    except Exception as e:
        print(f"Error during ping sweep: {e}")

    return live_hosts

# Port Scan
def scan_port(args):
    ip, port = args
    try:
        response = sr1(IP(dst=ip)/TCP(dport=port, flags="S"), timeout=1, verbose=0)
        if response is not None and response.haslayer(TCP) and response[TCP].flags == "SA":
            return port
        return None
    except Exception as e:
        with print_lock:
            print(f"Error scanning port {port} on {ip}: {e}")
        return None

def port_scan(ip, ports):
    print(f"Starting Port Scan on {ip}")
    open_ports = []

    try:
        num_threads = os.cpu_count()
        total_ports = len(ports)
        
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = {executor.submit(scan_port, (ip, port)): port for port in ports}
            for i, future in enumerate(as_completed(futures), start=1):
                port = futures[future]
                result = future.result()
                with print_lock:
                    print(f"Scanning {ip}: {i}/{total_ports}", end="\r")
                    if result is not None:
                        print(f"\nPort {port} is open on host {ip}")
                        open_ports.append(result)

    except Exception as e:
        print(f"Error during port scan: {e}")

    return open_ports

# Simple Password Strength Checker
def check_password_strength(password):
    print(f"Checking password strength for: {password}")
    try:
        length = len(password) >= 8
        lower = re.search(r"[a-z]", password) is not None
        upper = re.search(r"[A-Z]", password) is not None
        digit = re.search(r"\d", password) is not None
        special = re.search(r"[@$!%*?&#]", password) is not None

        if all([length, lower, upper, digit, special]):
            print("Password is strong.")
        else:
            print("Password is weak.")
            if not length:
                print("The password should be at least 8 characters long.")
            if not lower:
                print("The password should contain at least one lowercase letter.")
            if not upper:
                print("The password should contain at least one uppercase letter.")
            if not digit:
                print("The password should contain at least one digit.")
            if not special:
                print("The password should contain at least one special character (@$!%*?&#).")

    except Exception as e:
        print(f"Error during password strength check: {e}")

def main():
    print("Cybersecurity Tool")
    print("1. Ping Sweep")
    print("2. Port Scan")
    print("3. Password Strength Checker")
    print("4. Exit")
    
    while True:
        choice = input("Choose an option (1/2/3/4): ")
        if choice == '1':
            network = input("Enter the network address (e.g., 192.168.1.0): ")
            netmask = input("Enter the netmask (e.g., 24): ")
            live_hosts = ping_sweep(network, netmask)
            if live_hosts:
                print(f"Live hosts: {live_hosts}")
            else:
                print("No live hosts found.")
        elif choice == '2':
            ip = input("Enter the IP address to scan: ")
            ports = input("Enter the port range (e.g., 1-1024): ")
            port_start, port_end = map(int, ports.split('-'))
            open_ports = port_scan(ip, range(port_start, port_end + 1))
            if open_ports:
                print(f"Open ports on {ip}: {open_ports}")
            else:
                print("No open ports found.")
        elif choice == '3':
            password = input("Enter the password to check: ")
            check_password_strength(password)
        elif choice == '4':
            print("Exiting...")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()
