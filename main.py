from network import Network
from scanner import scan_list
from time import time
from storage import Storage
from logger import *

class Main:
    def __init__(self):
        self.network = Network()
        self.starttime = time.time()
        self.SAVEFOLDER = "./"
        self.sniff_path = self.SAVEFOLDER + "sniff.pcap"
        self.scanname = "network-scan.txt"
        self.portlist = [
                          80,    # HTTP
                          443,   # HTTPS
                          53,    # DNS
                          67,    # DHCP (Server)
                          68,    # DHCP (Client)
                          22,    # SSH
                          21,    # FTP
                          23,    # Telnet
                          161,   # SNMP
                          25,    # SMTP
                          110,   # POP3
                          123,   # NTP
                          69,    # TFTP
                          179,   # BGP
                          514,   # Syslog
                          20,    # FTP (Data Transfer)
                          8080,  # HTTP Alternate
                          4433,  # HTTPS Alternate
                          143,   # IMAP
                          993,   # IMAPS (Secure IMAP)
                          1194,  # OpenVPN
                          1723,  # PPTP (VPN)
                          3306,  # MySQL Database
                          3389,  # RDP (Remote Desktop)
                          5900   # VNC (Remote Access)
                        ]
        self.network_range = None
        self.active_ips = None
        self.ip_ports = None

    def runner(self):
        log_info("Starting scan...")
        self.active_ips = self.network.arp_scan()
        self.network_range = self.network.subnet_prefix_length
        self.network.sniff(timeout=10,filepath=self.sniff_path)
        self.ip_ports = scan_list(self.network.baseIp+'1', self.portlist, type="half", workers=15)
        log_success(f"Scan complete in {(time.time() - self.starttime):.2f} seconds")

    def format_active_ips(self):
        log_info("Formatting active ips...")
        r = "Alife IPs:\n----------\n"
        for i in self.active_ips:
            r += i["ip"] + ' : ' + i["mac"] + "\n"
        log_success("Formatting complete")
        return r

    def format_ip_ports(self):
        log_info("Formatting ip ports...")
        r = "Open Ports on " + self.network.baseIp+'1' + ":\n-----------------------------\n"
        r += str(self.ip_ports)
        log_success("Formatting complete")
        return r

    def save(self):
        try:
            log_info("Saving results...")
            r = "Network Range: " + str(self.network_range) + "\n\n"+ self.format_active_ips() + "\n\n" + self.format_ip_ports() + "\n\n" +"Time Elapsed: " + str(time.time() - self.starttime) + " seconds" + "\n" + "Sniff Path: " + self.sniff_path
            Storage(self.SAVEFOLDER, self.scanname, r).save()
            log_success("Saving complete")
        except Exception as e:
            log_error(e)

    def printout(self):
        print(self.active_ips)
        print(self.network_range)
        print(self.ip_ports)
        print(self.sniff_path)

if __name__ == "__main__":
    main = Main()
    main.runner()
    main.save()
    main.printout()