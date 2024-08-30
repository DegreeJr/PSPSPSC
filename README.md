# PSPSPSC

## Overview
PSPSPSC (Ping Sweeper, Port Scan, and Password Strength Checker) is a Python-based cybersecurity tool designed to enhance network security by offering three essential functionalities:

Ping Sweeper: Scans a specified network range to identify active hosts. This tool is useful for network administrators to map out all live devices within a subnet, providing insights into potential unauthorized devices or network issues.

Port Scan: Checks for open ports on a given IP address within a specified range. This feature helps identify potential vulnerabilities by revealing services running on the target machine that could be exploited.

Password Strength Checker: Evaluates the strength of user-provided passwords, ensuring they meet security standards by checking for length, use of uppercase and lowercase letters, digits, and special characters. This feature is vital for educating users on creating strong, secure passwords to protect their accounts from unauthorized access.

PSPSPSC is a comprehensive tool aimed at both improving network security and promoting best practices in password management. It’s suitable for use by IT professionals and cybersecurity enthusiasts alike.

## Requirements
To run this tool, you need to have Python 3.x installed along with the following Python libraries:
- `scapy`
- `ipaddress`
- `concurrent.futures`
- `threading`
- `re`

You can install the required libraries using pip:
```bash
pip install scapy
```

## Running the Tool
```bash
git clone https://github.com/DegreeJr/PSPSPSC
cd  PSPSPSC/
sudo python3 pspspsc.py
```

##Demo
https://youtu.be/mychEGUalm8

