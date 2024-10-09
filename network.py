from socket import AF_INET
import psutil
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP
from scapy.layers.l2 import Ether, ARP
from logger import *
import scanner

class Packet:
    def __init__(self, ip:str,iprange:int=None, port:int=None):
        self.IP = ip
        self.Range = iprange
        self.port = port
        self.full_ip = f"{self.IP}/{self.Range}"
        self.timeout = 0.75

    def ICMP(self):
        icmp = IP(dst=self.IP) / ICMP()
        return sr1(icmp, timeout=self.timeout, verbose=0)

    def SYN(self):
        syn = IP(dst=self.IP) / TCP(dport=self.port, flags="S")
        return sr1(syn, timeout=self.timeout, verbose=0)

    def RST(self):
        rst = IP(dst=self.IP) / TCP(dport=self.port, flags="R")
        return sr1(rst, timeout=self.timeout, verbose=0)

    def ARP(self):
        arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.full_ip)
        return srp(arp, timeout=self.timeout, verbose=False)

class Network:
    def __init__(self):
        self.subnetmask = None
        self.baseIp:str = ''
        self.activeIp:list = []
        self.firstIp:str = self.setBaseIP() + '0'
        self.subnet_prefix_length = None

    @property
    def get_own_ip(self):
        try:
            log_info("Getting own IP")
            return socket.gethostbyname(socket.gethostname())
        except Exception as e:
            log_error(e)
            return None

    def setBaseIP(self):
        self.baseIp = self.get_own_ip
        self.baseIp = self.baseIp.split(".")
        self.baseIp = self.baseIp[0] + "." + self.baseIp[1] + "." + self.baseIp[2] + "."
        return self.baseIp

    @property
    def get_subnet_mask(self,interface_name="WLAN"):
        # Get the network interfaces
        interfaces = psutil.net_if_addrs()

        if interface_name is None:
            # Use the first available interface if none is specified
            interface_name = next(iter(interfaces))

        try:
            log_info(f"Getting subnet mask for {interface_name} ...")
            # Get the addresses for the specified interface
            interface_info = interfaces[interface_name]
            for addr in interface_info:
                if addr.family == AF_INET:  # Check for IPv4 addresses
                    self.subnetmask = addr.netmask
                    return addr.netmask
        except KeyError:
            log_error(f"Interface '{interface_name}' not found.")
            return None

    @staticmethod
    def ge_prefixlength_from_subnetmask(subnetmask):
        log_info(f"Getting prefix length from subnetmask {subnetmask} ...")
        match subnetmask:
            case '255.255.255.0':
                return 24
            case '255.255.0.0':
                return 16
            case '255.0.0.0':
                return 8
            case '255.255.255.255':
                return 32
            case '255.255.255.254':
                return 31
            case '255.255.255.252':
                return 30
            case '255.255.255.248':
                return 29
            case '255.255.255.240':
                return 28
            case '255.255.255.224':
                return 27
            case '255.255.255.192':
                return 26
            case '255.255.255.128':
                return 25
            case '255.255.255.0':
                return 24
            case '255.255.254.0':
                return 23
            case '255.255.252.0':
                return 22
            case '255.255.248.0':
                return 21
            case '255.255.240.0':
                return 20
            case '255.255.224.0':
                return 19
            case '255.255.192.0':
                return 18
            case '255.255.128.0':
                return 17
            case _:
                return None

    @property
    def get_subnet_prefix_length(self):
        if self.subnet_prefix_length is None:
            s = self.get_subnet_mask
            self.subnet_prefix_length = self.ge_prefixlength_from_subnetmask(s)
        return self.subnet_prefix_length

    def arp_scan(self):
        try:
            log_info("ARP scan started")
            answered_list, unanswered_list = scanner.Packet(self.firstIp,iprange=self.get_subnet_prefix_length).ARP()
            r:list[dict] = []
            for sent, received in answered_list:
                r.append({"ip": received.psrc, "mac": received.hwsrc})
            log_success("ARP scan completed")
            return r
        except Exception as e:
            log_error(e)
            return None

    @staticmethod
    def sniff(timeout:float=10,filepath:str=None):
        try:
            if filepath is not None:
                if not filepath.endswith(".pcap"):
                    log_error("Sniffing filepath needs to end with .pcap")
                    return None
                log_info(f"Sniffing for {timeout} seconds and saving to {filepath} ...")
                packets = sniff(timeout=10)
                wrpcap(filepath, packets)
            else:
                log_info(f"Sniffing for {timeout} seconds ...")
                packets = sniff(timeout=timeout,store=0)
            log_success("Sniffing completed")
            return packets
        except Exception as e:
            log_error(e)
         #   return None

if __name__ == "__main__":
    print(Network().arp_scan())
