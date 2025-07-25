from scapy.all import ARP, Ether, srp
import socket

def print_banner():
    banner = r"""
 _____ _        __   __        _     
|_   _| |       \ \ / /       | |    
  | | | |_ ___   \ V /__ _ ___| |__  
  | | | __/ __|   \ // _` / __| '_  \ 
 _| |_| |_\__ \   | | (_| \__ \ | | |
 \___/ \__|___/   \_/\__,_|___/_| |_|
    """
    print(banner)

def print_fancy_box(text, width=77):
    top_left = "┌"
    top_right = "┐"
    bottom_left = "└"
    bottom_right = "┘"
    horizontal = "═"
    vertical = "█"

    print(top_left + horizontal * width + top_right)
    print(vertical + " " * width + vertical)
    print(vertical + text.center(width) + vertical)
    print(vertical + " " * width + vertical)
    print(bottom_left + horizontal * width + bottom_right)

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def guess_device_type(mac, hostname=None):
    mac_prefix = mac.upper()[0:8].replace(":", "-")

    known_types = {
        "00-50-56": "VMware",
        "08-00-27": "VirtualBox",
        "00-1C-42": "Parallels VM",
        "3C-5A-B4": "Android Device",
        "FC-18-3C": "Samsung",
        "00-16-6C": "Apple Device",
        "00-1B-63": "Cisco Router",
        "F4-09-D8": "Xiaomi",
        "AC-BC-32": "Huawei",
        "B8-27-EB": "Raspberry Pi",
    }

    for prefix, device in known_types.items():
        if mac_prefix.startswith(prefix):
            return device

    if hostname and hostname != "Unknown":
        h = hostname.lower()
        if "android" in h:
            return "Android Device"
        elif "vm" in h:
            return "Virtual Machine"
        elif "win" in h:
            return "Windows PC"
        elif "iphone" in h or "ipad" in h:
            return "Apple Device"
        elif "raspberry" in h:
            return "Raspberry Pi"

    return "Unknown Device"

def print_table_box(clients):
    width = 77
    horizontal = "─"
    vertical = "|"

    print(" " + "_" * width)
    header = "  IP            MAC Address        Count     Len  Hostname / Device Type"
    print(vertical + header.ljust(width - 1) + vertical)
    print(vertical + horizontal * (width - 1) + vertical)

    for mac, data in clients.items():
        ip_str = data['ip']
        mac_str = mac
        count_str = str(data['count'])
        len_str = str(data['len'])

        hostname = get_hostname(ip_str)
        device_type = guess_device_type(mac, hostname)
        label = hostname if hostname != "Unknown" else device_type

        row = f" {ip_str:<14}  {mac_str:<17}  {count_str:>6}  {len_str:>6}  {label:<25}"
        print(vertical + row.ljust(width - 1) + vertical)

    print(" " + "└" + "─" * (width - 2) + "┘")

def scan_network(ip_range):
    print(f"\nScanning network: {ip_range} ...\n")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=3, verbose=0)[0]

    clients = {}
    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc
        if mac not in clients:
            clients[mac] = {'ip': ip, 'count': 1, 'len': len(received)}
        else:
            clients[mac]['count'] += 1
            clients[mac]['len'] += len(received)

    print_table_box(clients)

if __name__ == "__main__":
    print_banner()
    print_fancy_box("Your Network Configuration")
    ip_range = input("Enter IP or subnet to scan (e.g., 192.168.1.0/24): ").strip()
    if ip_range:
        scan_network(ip_range)
    else:
        print("Please enter a valid IP or subnet.")
