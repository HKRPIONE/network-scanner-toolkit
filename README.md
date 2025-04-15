
# Network Scanner Toolkit

A Python-based toolkit for network scanning and secure message/file encryption.

## Features
- **Ping Sweep**: Discover live hosts on a network (e.g., `192.168.1.0/24`).
- **Port Scan**: Scan for open TCP ports and identify services.
- **Encrypt/Decrypt**: Securely encrypt/decrypt messages or files using Fernet symmetric encryption.

## Prerequisites
- Python 3.6 or higher
- Required Python packages (see `requirements.txt`)

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/network-scanner-toolkit.git
   cd network-scanner-toolkit
Install dependencies:
```bash

pip install -r requirements.txt
```

## Usage
Run the script:
```bash
python network_scanner.py
```

Follow the menu:

Ping Sweep: Enter a network prefix (e.g., 192.168.1).
Port Scan: Enter a target IP/domain and port range.
Encrypt/Decrypt: Choose to encrypt/decrypt a message or file, using a generated or existing key.
Exit: Close the program.
Note: Ping sweep may require root privileges for raw ICMP sockets on some systems.

## Example
```bash
$ python network_scanner.py
=== Network Scanner & Toolkit ===
1. Ping Sweep
2. Port Scan
3. Encrypt/Decrypt Message
4. Exit

Select option: 3
[*] Encrypt/Decrypt Message
Encrypt or Decrypt? (e/d): e
Use existing key? (y/n) [default n]: n
Save key to file? (enter path or leave blank for no save): key.txt
[+] Key saved to key.txt
[+] Generated key: gVqELY5LNWKs0U9C7L6GXCoP2j5yVFtJSjqKiSRuzXM=
Encrypt/Decrypt a file? (y/n) [default n]: n
Enter message to encrypt: ffff
[+] Encrypted message: gAAAAABn_pyTUY_07kbHc2PGIf8X62X5dzfcnT24UjAgJ2FEPoXxQ1C3DNBn-c2WdiJDvmi0-VI33IGT51blM2n5vW0OS_m4hQ==
```

