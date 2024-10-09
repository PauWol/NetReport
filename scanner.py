from concurrent.futures import ThreadPoolExecutor
import concurrent.futures
import scapy.all
from scapy.layers.inet import ICMP, IP , TCP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
from logger import *



class Packet:
    def __init__(self, ip:str,iprange:int=None, port:int=None):
        self.IP = ip
        self.Range = iprange
        self.port = port
        self.full_ip = f"{self.IP}/{self.Range}"
        self.timeout = 0.75

    def ICMP(self):
        icmp = IP(dst=self.IP) / ICMP()
        return scapy.all.sr1(icmp, timeout=self.timeout, verbose=0)

    def SYN(self):
        syn = IP(dst=self.IP) / TCP(dport=self.port, flags="S")
        return scapy.all.sr1(syn, timeout=self.timeout, verbose=0)

    def RST(self):
        rst = IP(dst=self.IP) / TCP(dport=self.port, flags="R")
        return scapy.all.sr1(rst, timeout=self.timeout, verbose=0)

    def ARP(self):
        arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.full_ip)
        return srp(arp, timeout=self.timeout, verbose=False)

def ping(ip:str):
    try:
        log_info(f"Pinging {ip} ...")
        if Packet(ip).ICMP() is None:
            log_success(f"Host {ip} is down")
            return False
        else:
            log_success(f"Host {ip} is up")
            return ip
    except Exception as e:
        log_error(e)
        return False

def validate_scan(response):
    if response is None or not response.haslayer(TCP) or response.getlayer(TCP).flags == 0x14:
        return False
    if response.getlayer(TCP).flags == 0x12:  # SYN-ACK (flags=0x12)
        return True

def full_scan(ip:str,port:int):
    try:
        log_info(f"TCP full scan on {ip}:{port} ...")
        response = Packet(ip,port=port).SYN()
        if validate_scan(response):
            Packet(ip,port=port).RST()
            return True
        return False
    except Exception as e:
        log_error(e)
        return False

def half_scan(ip:str,port:int):
    try:
        log_info(f"TCP half scan on {ip}:{port} ...")
        response = Packet(ip,port=port).SYN()
        if validate_scan(response):
            return True
        return False
    except Exception as e:
        log_error(e)
        return False

def scan_list(ip, ports:list,type="full",workers=15):
    if type == "half":
        partial_scan = lambda port: half_scan(ip, port)
    elif type == "full":
        partial_scan = lambda port: full_scan(ip, port)
    else:
        log_error(message="Invalid scan type {type}. Must be half or full")
        return 0
    r:list = []
    log_info(f"Starting {type} scan on {ip} with {ports} and {workers} workers...")
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(partial_scan, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            result = future.result()

            if result:
                r.append(port)
    end_time = time.time()
    log_success(f"Scan completed in {(end_time - start_time):.2f} seconds")
    return r

if __name__ == "__main__":
            ip = "192.168.178.1"
            ports = [1, 2, 3, 4,22,443,12,21,80,3000]
            scan_list(ip, ports)
