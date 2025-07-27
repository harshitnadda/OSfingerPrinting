import sys
import socket
from urllib.parse import urlparse
from scapy.all import IP, TCP, sr1
from termcolor import colored

def get_ip_from_input(user_input):
    """Resolve IP/domain/URL to an IP address"""
    try:
        # If it's a URL, extract hostname
        if "://" in user_input:
            parsed = urlparse(user_input)
            hostname = parsed.hostname
        else:
            hostname = user_input

        # If already an IP, return as is
        socket.inet_aton(hostname)
        return hostname
    except socket.error:
        # Not an IP, resolve domain
        try:
            ip = socket.gethostbyname(hostname)
            return ip
        except socket.gaierror:
            return None

def detect_os(target_ip):
    print(colored(f"[+] Probing {target_ip}...\n", "cyan"))
    pkt = IP(dst=target_ip) / TCP(dport=80, flags="S")
    resp = sr1(pkt, timeout=3, verbose=0)

    if resp is None:
        print(colored("[-] No response. Host may be down or filtered.", "red"))
        return

    ttl = resp.ttl
    window = resp[TCP].window
    df_flag = bool(resp.flags.DF)
    tos = resp.tos

    print(colored(f"[DEBUG] TTL: {ttl}, Window Size: {window}, DF: {df_flag}, ToS: {tos}\n", "yellow"))

    # Simple matching
    if ttl <= 64 and window in [32120, 5840]:
        print(colored("Likely OS: Linux/FreeBSD", "green"))
    elif ttl <= 128:
        print(colored("Likely OS: Windows", "green"))
    elif ttl >= 200:
        print(colored("Likely OS: Cisco/Network Device", "green"))
    else:
        print(colored("OS detection uncertain.", "red"))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: sudo python detect_os.py <IP/Domain/URL>")
        sys.exit(1)

    target = sys.argv[1]
    target_ip = get_ip_from_input(target)

    if not target_ip:
        print(colored("[-] Could not resolve target to IP.", "red"))
        sys.exit(1)

    print(colored(f"[+] Target resolved to IP: {target_ip}", "cyan"))
    detect_os(target_ip)
