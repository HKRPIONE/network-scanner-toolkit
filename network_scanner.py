import socket
import struct
import time
import os
import re
import subprocess
import platform
import requests
import json
import base64
from concurrent.futures import ThreadPoolExecutor
from cryptography.fernet import Fernet, InvalidToken
import ssl

# ----------------------------- UTILITY FUNCTIONS -----------------------------
def is_valid_ip(ip):
    """Check if the given string is a valid IPv4 address."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def is_valid_prefix(prefix):
    """Check if the network prefix is valid (e.g., 192.168.1)."""
    prefix = prefix.strip()
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if not re.match(pattern, prefix):
        return False
    try:
        return all(0 <= int(part) <= 255 for part in prefix.split("."))
    except ValueError:
        return False

# ----------------------------- DOMAIN TO IP CONVERSION -----------------------------
def domain_to_ip(domain):
    """Resolve a domain name to an IP address."""
    if not domain or not isinstance(domain, str):
        print("[-] Invalid domain name.")
        return None
    try:
        ip = socket.gethostbyname(domain.strip())
        print(f"[+] Resolved {domain} to IP: {ip}")
        return ip
    except socket.gaierror:
        print(f"[-] Unable to resolve domain {domain}.")
        return None
    except Exception as e:
        print(f"[-] Error resolving domain {domain}: {e}")
        return None

# ----------------------------- PING SWEEP -----------------------------
def calculate_checksum(data):
    """Calculate ICMP checksum."""
    checksum = 0
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            word = (data[i] << 8) + data[i + 1]
        else:
            word = data[i] << 8
        checksum += word
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return ~checksum & 0xFFFF

def send_icmp_echo(ip, timeout=2):
    """Send a single ICMP echo request and check for a reply using raw sockets."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)
        
        # Create ICMP packet (type 8, code 0)
        packet_id = os.getpid() & 0xFFFF
        seq = 1
        header = struct.pack("!BBHHH", 8, 0, 0, packet_id, seq)
        data = b"pingtest"
        packet = header + data
        checksum = calculate_checksum(packet)
        packet = struct.pack("!BBHHH", 8, 0, checksum, packet_id, seq) + data
        
        sock.sendto(packet, (ip, 0))
        start = time.time()
        
        while time.time() - start < timeout:
            try:
                reply, _ = sock.recvfrom(1024)
                # Check if it's an ICMP echo reply (type 0)
                if len(reply) >= 20 and reply[20] == 0:
                    return ip
            except socket.timeout:
                continue
        return None
    except PermissionError:
        print(f"[-] ICMP ping requires root privileges on {ip}. Falling back to subprocess ping.")
        return None
    except socket.error as e:
        print(f"[-] Socket error pinging {ip}: {e}")
        return None
    except Exception as e:
        print(f"[-] Error pinging {ip}: {e}")
        return None
    finally:
        sock.close()

def ping_host_subprocess(ip, timeout=2):
    """Fallback ping using subprocess for non-privileged users."""
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        timeout_flag = "-w" if platform.system().lower() == "windows" else "-W"
        timeout_val = str(timeout * 1000) if platform.system().lower() == "windows" else str(timeout)
        result = subprocess.run(
            ["ping", param, "1", timeout_flag, timeout_val, ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return ip if result.returncode == 0 else None
    except Exception as e:
        print(f"[-] Subprocess ping error for {ip}: {e}")
        return None

def ping_sweep(prefix):
    """
    Perform an ICMP-based ping sweep on the given network prefix.
    Input: Network prefix (e.g., '192.168.1' to scan 192.168.1.1 to 192.168.1.254).
    """
    if not is_valid_prefix(prefix):
        print("[-] Invalid network prefix. Use format '192.168.1' to scan 192.168.1.0/24.")
        return []

    print(f"\n[*] Pinging network {prefix}.0/24 (scanning {prefix}.1 to {prefix}.254)...")
    live_hosts = []
    ips = [f"{prefix}.{i}" for i in range(1, 255)]
    max_workers = min(50, len(ips) // 4 + 1)  # Dynamic worker count

    # Try ICMP raw socket ping first
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(send_icmp_echo, ips))

    live_hosts = [ip for ip in results if ip]

    # If no hosts found and ICMP failed (likely permissions), try subprocess fallback
    if not live_hosts:
        print("[*] No hosts found with ICMP. Attempting subprocess ping...")
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(ping_host_subprocess, ips))
        live_hosts = [ip for ip in results if ip]

    if live_hosts:
        print(f"[+] Found {len(live_hosts)} live hosts:")
        for ip in live_hosts:
            print(f"  - {ip}")
    else:
        print("[-] No live hosts found.")
    
    return live_hosts

# ----------------------------- NETWORK SCANNER -----------------------------
def scan_port(target_ip, port, timeout=0.5):
    """Scan a single port on the target IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            return port, service
        return None
    except socket.error as e:
        print(f"[-] Socket error on port {port}: {e}")
        return None
    except Exception as e:
        print(f"[-] Error scanning port {port}: {e}")
        return None
    finally:
        sock.close()

def scan_ports(target_ip, start_port=1, end_port=1024, common=False, timeout=0.5):
    """Scan a range of ports or common ports on the target IP."""
    if not is_valid_ip(target_ip):
        print("[-] Invalid IP address.")
        return []

    common_ports = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3389, 8080]
    ports = common_ports if common else range(start_port, end_port + 1)
    
    if not common and not (1 <= start_port <= end_port <= 65535):
        print("[-] Invalid port range. Use ports between 1 and 65535.")
        return []

    print(f"\n[*] Scanning {target_ip} for {'common ports' if common else f'ports {start_port}-{end_port}'}...")
    open_ports = []

    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda p: scan_port(target_ip, p, timeout), ports)
    
    open_ports = [result for result in results if result]
    
    if open_ports:
        print(f"[+] Found {len(open_ports)} open ports:")
        for port, service in open_ports:
            print(f"  - Port {port}/tcp ({service})")
    else:
        print("[-] No open ports found.")
    
    return open_ports

# ----------------------------- BANNER GRABBING -----------------------------
def grab_banner(ip, port, use_ssl=False, retries=2):
    """Grab the banner from a specific IP and port, with optional SSL and retries."""
    if not is_valid_ip(ip):
        print("[-] Invalid IP address.")
        return None
    
    if not (1 <= port <= 65535):
        print("[-] Invalid port number.")
        return None

    attempt = 0
    while attempt < retries:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            
            if use_ssl:
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=ip)
            
            sock.connect((ip, port))
            banner = sock.recv(1024).decode(errors="ignore").strip()
            sock.close()
            
            if banner:
                print(f"[+] Banner from {ip}:{port} (SSL: {use_ssl}): {banner}")
                return banner
            print(f"[-] No banner received from {ip}:{port}.")
            return None
            
        except ssl.SSLError as e:
            print(f"[-] SSL error at {ip}:{port}: {e}")
            return None
        except socket.timeout:
            print(f"[-] Timeout connecting to {ip}:{port} (attempt {attempt + 1}/{retries}).")
        except socket.error as e:
            print(f"[-] Connection error at {ip}:{port}: {e}")
        except Exception as e:
            print(f"[-] Error grabbing banner from {ip}:{port}: {e}")
        finally:
            sock.close()
        
        attempt += 1
        time.sleep(0.5)  # Brief pause before retry
    
    print(f"[-] Failed to grab banner from {ip}:{port} after {retries} attempts.")
    return None

# ----------------------------- CVE LOOKUP -----------------------------
cve_cache = {}  # Simple in-memory cache for CVE queries

def sanitize_query(query):
    """Sanitize query string for API safety."""
    return "".join(c for c in query if c.isalnum() or c in " .-").strip()

def search_cve(banner):
    """Search for CVEs using NVD API based on the banner."""
    if not banner or len(banner.strip()) < 5:
        print("[-] Invalid or too short banner for CVE lookup.")
        return

    sanitized = sanitize_query(banner)
    if not sanitized:
        print("[-] Banner contains no valid characters for CVE search.")
        return

    # Check cache first
    if sanitized in cve_cache:
        print(f"[*] Using cached CVE results for: {sanitized[:30]}...")
        results = cve_cache[sanitized]
        if results:
            print(f"[+] Found {len(results)} CVEs (showing up to 5):")
            for item in results[:5]:
                print(f"  - {item['id']}: {item['description'][:100]}...")
        else:
            print("[-] No CVEs found in cache.")
        return

    print(f"\n[*] Searching CVEs for: {sanitized[:30]}...")
    try:
        headers = {"User-Agent": "NetworkScanner/1.0"}
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={sanitized}"
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            results = []
            if "vulnerabilities" in data:
                for vuln in data["vulnerabilities"]:
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "Unknown")
                    description = cve.get("descriptions", [{}])[0].get("value", "No description")[:100]
                    results.append({"id": cve_id, "description": description})
                
                cve_cache[sanitized] = results  # Cache results
                
                if results:
                    print(f"[+] Found {len(results)} CVEs (showing up to 5):")
                    for item in results[:5]:
                        print(f"  - {item['id']}: {item['description']}...")
                else:
                    print("[-] No CVEs found.")
            else:
                print("[-] Unexpected response format from NVD API.")
        elif response.status_code == 429:
            print("[-] Rate limit exceeded for CVE lookup. Try again later.")
        else:
            print(f"[-] CVE lookup failed: HTTP {response.status_code}")
    except requests.Timeout:
        print("[-] CVE lookup timed out.")
    except requests.ConnectionError:
        print("[-] Network error during CVE lookup.")
    except ValueError:
        print("[-] Invalid JSON response from CVE API.")
    except requests.RequestException as e:
        print(f"[-] CVE lookup error: {e}")
    except Exception as e:
        print(f"[-] Unexpected error in CVE lookup: {e}")

# ----------------------------- ENCRYPT/DECRYPT MESSAGE -----------------------------
def is_valid_key(key):
    """Validate if the key is a proper Fernet key (32-byte base64-encoded)."""
    try:
        if isinstance(key, str):
            key = key.strip().encode('utf-8')
        base64.b64decode(key, validate=True)
        Fernet(key)  # Test key initialization
        return True
    except (base64.binascii.Error, ValueError, TypeError):
        return False

def generate_key(save_to_file=None):
    """Generate a Fernet encryption key and optionally save to file."""
    try:
        key = Fernet.generate_key()
        if save_to_file:
            try:
                with open(save_to_file, "wb") as f:
                    f.write(key)
                print(f"[+] Key saved to {save_to_file}")
            except (OSError, PermissionError) as e:
                print(f"[-] Failed to save key to {save_to_file}: {e}")
                return None
        return key
    except Exception as e:
        print(f"[-] Error generating key: {e}")
        return None

def encrypt_message(key, message=None, input_file=None, output_file=None):
    """Encrypt a message or file using the provided key."""
    if not is_valid_key(key):
        print("[-] Invalid or corrupted key. Must be a 32-byte base64-encoded Fernet key.")
        return None
    
    try:
        f = Fernet(key)
        if input_file:
            if not os.path.exists(input_file):
                print(f"[-] Input file not found: {input_file}")
                return None
            if not os.path.getsize(input_file):
                print(f"[-] Input file is empty: {input_file}")
                return None
            try:
                with open(input_file, "rb") as f_in:
                    data = f_in.read()
                encrypted = f.encrypt(data)
                if output_file:
                    try:
                        with open(output_file, "wb") as f_out:
                            f_out.write(encrypted)
                        print(f"[+] Encrypted file saved to {output_file}")
                    except (OSError, PermissionError) as e:
                        print(f"[-] Failed to save encrypted file to {output_file}: {e}")
                        return None
                return encrypted
            except (OSError, PermissionError) as e:
                print(f"[-] Error reading input file {input_file}: {e}")
                return None
        elif message:
            if not message.strip():
                print("[-] Message cannot be empty.")
                return None
            encrypted = f.encrypt(message.encode('utf-8'))
            encrypted_str = encrypted.decode('utf-8')
            return encrypted_str
        else:
            print("[-] No message or input file provided.")
            return None
    except InvalidToken:
        print("[-] Encryption failed: Invalid key or data.")
        return None
    except Exception as e:
        print(f"[-] Encryption error: {e}")
        return None

def decrypt_message(key, encrypted_message=None, input_file=None, output_file=None):
    """Decrypt a message or file using the provided key."""
    if not is_valid_key(key):
        print("[-] Invalid or corrupted key. Must be a 32-byte base64-encoded Fernet key.")
        return None
    
    if isinstance(key, str):
        key = key.strip().encode('utf-8')
    
    try:
        f = Fernet(key)
        if input_file:
            if not os.path.exists(input_file):
                print(f"[-] Input file not found: {input_file}")
                return None
            if not os.path.getsize(input_file):
                print(f"[-] Input file is empty: {input_file}")
                return None
            try:
                with open(input_file, "rb") as f_in:
                    data = f_in.read()
                print(f"[*] Attempting to decrypt file: {input_file}")
                decrypted = f.decrypt(data)
                if output_file:
                    try:
                        with open(output_file, "wb") as f_out:
                            f_out.write(decrypted)
                        print(f"[+] Decrypted file saved to {output_file}")
                    except (OSError, PermissionError) as e:
                        print(f"[-] Failed to save decrypted file to {output_file}: {e}")
                        return None
                return decrypted
            except (OSError, PermissionError) as e:
                print(f"[-] Error reading input file {input_file}: {e}")
                return None
        elif encrypted_message:
            if not encrypted_message.strip():
                print("[-] Encrypted message cannot be empty.")
                return None
            encrypted_message = encrypted_message.strip()
            print(f"[*] Received encrypted message: {encrypted_message[:30]}...")
            decrypted = f.decrypt(encrypted_message.encode('utf-8'))
            return decrypted.decode('utf-8')
        else:
            print("[-] No encrypted message or input file provided.")
            return None
    except InvalidToken:
        print(f"[-] Decryption failed: Incorrect key or corrupted data (message: {encrypted_message[:30] if encrypted_message else 'N/A'}...). Ensure the key matches the one used for encryption.")
        return None
    except ValueError as e:
        print(f"[-] Decryption failed: Invalid encrypted data format ({e}) (message: {encrypted_message[:30] if encrypted_message else 'N/A'}...). Check the encrypted message.")
        return None
    except Exception as e:
        print(f"[-] Decryption error: {e} (message: {encrypted_message[:30] if encrypted_message else 'N/A'}...).")
        return None

# ----------------------------- MAIN MENU -----------------------------
def main():
    print("\n=== Network Scanner & Toolkit ===")
    
    while True:
        print("\n1. Ping Sweep")
        print("2. Port Scan")
        print("3. Encrypt/Decrypt Message")
        print("4. Exit")
        
        choice = input("\nSelect option: ").strip()
        
        if choice == "1":
            prefix = input("Enter network prefix (e.g., '192.168.1' for 192.168.1.0/24): ").strip()
            ping_sweep(prefix)
        
        elif choice == "2":
            target = input("Enter target IP or domain: ").strip()
            if not target:
                print("[-] Target cannot be empty.")
                continue
            ip = domain_to_ip(target) if not is_valid_ip(target) else target
            if not ip:
                print("[-] Invalid target.")
                continue
            scan_type = input("Scan common ports only? (y/n) [default n]: ").strip().lower() == "y"
            if not scan_type:
                start_port = input("Enter start port [default 1]: ").strip() or "1"
                end_port = input("Enter end port [default 1024]: ").strip() or "1024"
                timeout = input("Enter timeout in seconds [default 0.5]: ").strip() or "0.5"
                try:
                    start_port = int(start_port)
                    end_port = int(end_port)
                    timeout = float(timeout)
                    scan_ports(ip, start_port, end_port, common=False, timeout=timeout)
                except ValueError:
                    print("[-] Invalid input for ports or timeout.")
            else:
                scan_ports(ip, common=True)
        
        elif choice == "3":
            print("\n[*] Encrypt/Decrypt Message")
            action = input("Encrypt or Decrypt? (e/d): ").strip().lower()
            if action not in ["e", "d"]:
                print("[-] Invalid action. Use 'e' for encrypt or 'd' for decrypt.")
                continue
                
            # Key handling
            key_source = input("Use existing key? (y/n) [default n]: ").strip().lower() == "y"
            if key_source:
                key_input = input("Enter key file path or paste the key exactly as shown during encryption: ").strip()
                if not key_input:
                    print("[-] Key input cannot be empty.")
                    continue
                if os.path.exists(key_input):
                    try:
                        with open(key_input, "rb") as f:
                            key = f.read()
                        if not is_valid_key(key):
                            print(f"[-] Invalid key in file: {key_input}")
                            continue
                        print(f"[*] Loaded key from file: {key_input} (starts with: {key.decode('utf-8')[:8]}...)")
                    except (OSError, PermissionError) as e:
                        print(f"[-] Error reading key file {key_input}: {e}")
                        continue
                else:
                    key = key_input
                    if not is_valid_key(key):
                        print("[-] Invalid key string. Must be a 32-byte base64-encoded Fernet key.")
                        continue
                    print(f"[*] Using key starting with: {key[:8]}...")
            else:
                key_file = input("Save key to file? (enter path or leave blank for no save): ").strip()
                key = generate_key(key_file or None)
                if not key:
                    continue
                print(f"[+] Generated key: {key.decode('utf-8')} (save this for decryption)")
            
            # File or string operation
            use_file = input("Encrypt/Decrypt a file? (y/n) [default n]: ").strip().lower() == "y"
            if use_file:
                input_file = input("Enter input file path (e.g., 'data.txt' for encrypt, 'data.enc' for decrypt): ").strip()
                output_file = input("Enter output file path (e.g., 'data.enc' for encrypt, 'data.dec' for decrypt): ").strip()
                if not input_file or not output_file:
                    print("[-] File paths cannot be empty.")
                    continue
                if action == "e":
                    result = encrypt_message(key, None, input_file, output_file)
                    if not result:
                        print("[-] Encryption failed.")
                else:
                    result = decrypt_message(key, None, input_file, output_file)
                    if not result:
                        print("[-] Decryption failed.")
            else:
                if action == "e":
                    message = input("Enter message to encrypt: ").strip()
                    if not message:
                        print("[-] Message cannot be empty.")
                        continue
                    encrypted = encrypt_message(key, message)
                    if encrypted:
                        print(f"[+] Encrypted message: {encrypted} (copy this exactly for decryption)")
                else:
                    encrypted_message = input("Paste the encrypted message exactly as shown (e.g., gAAAA...): ").strip()
                    if not encrypted_message:
                        print("[-] Encrypted message cannot be empty.")
                        continue
                    decrypted = decrypt_message(key, encrypted_message)
                    if decrypted:
                        print(f"[+] Decrypted message: {decrypted}")
        
        elif choice == "4":
            print("[*] Exiting...")
            break
        
        else:
            print("[-] Invalid option.")

if __name__ == "__main__":
    main()