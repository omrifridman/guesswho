from scapy.all import rdpcap
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether, ARP
from mac_vendor_lookup import MacLookup


SPECIAL_MACS = ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")

LINUX_TTL = range(1, 64+1)
WINDOWS_TTL = range(64+1, 128+1)
LINUX_BROADCAST_MAC = "00:00:00:00:00:00"
WINDOWS_BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

MAC_INFO = {"MAC": "Unknown", "IP": "Unknown", "VENDOR": "Unknown", "BROADCAST MAC": "Unknown"}
IP_INFO = {"IP": "Unknown", "MAC": "Unknown", "IP VERSION": "Unknown", "TTL": "Unknown"}


class AnalyzeNetwork:
    def __init__(self, pcap_path):
        """
        pcap_path (string): path to a pcap file
        """

        self.pcap = rdpcap(pcap_path)


    def get_ips(self):
        """
        returns a list of ip addresses (strings) that appear in the pcap
        """

        ips = set()
        for packet in self.pcap:
            if ARP in packet:
                ips.add(packet[ARP].psrc)
                ips.add(packet[ARP].pdst)
            elif IP in packet:
                ips.add(packet[IP].dst)
                ips.add(packet[IP].src)

        return list(ips)


    def get_macs(self):
        """
        returns a list of MAC addresses (strings) that appear in the pcap
        """

        macs = set()
        for packet in self.pcap:
            if Ether in packet:
                if packet[Ether].dst not in SPECIAL_MACS:
                    macs.add(packet[Ether].dst)
                macs.add(packet[Ether].src)

            if ARP in packet:
                if packet[ARP].hwdst not in SPECIAL_MACS:
                    macs.add(packet[ARP].hwdst)
                macs.add(packet[ARP].hwsrc)

        return list(macs)


    def get_info_by_mac(self, mac):
        """
        returns a dict with all information about the device with given MAC address
        """

        mac_info = dict(MAC_INFO)

        mac_info["MAC"] = mac
        mac_info["VENDOR"] = MacLookup().lookup(mac)

        for packet in self.pcap:
            if ARP in packet:
                if packet[ARP].hwsrc == mac:
                    mac_info["IP"] = packet[ARP].psrc
                    break

                if packet[ARP].hwdst == mac:
                    mac_info["IP"] = packet[ARP].pdst
                    break
            elif IP in packet:
                if packet[Ether].src == mac:
                    mac_info["IP"] = packet[IP].src
                    break

        for packet in self.pcap:
            if ARP in packet:
                if packet[ARP].hwsrc == mac and packet[ARP].hwdst in (LINUX_BROADCAST_MAC, WINDOWS_BROADCAST_MAC):
                    mac_info["BROADCAST MAC"] = packet[ARP].hwdst
                    break

        return mac_info


    def get_info_by_ip(self, ip):
        """
        returns a dict with all information about the device with given IP address
        """

        ip_info = dict(IP_INFO)

        ip_info["IP"] = ip

        for packet in self.pcap:
            if ARP in packet:
                if packet[ARP].psrc == ip and packet[ARP].hwsrc not in SPECIAL_MACS:
                    ip_info["MAC"] = packet[ARP].hwsrc
                    break

                if packet[ARP].pdst == ip and packet[ARP].hwdst not in SPECIAL_MACS:
                    ip_info["MAC"] = packet[ARP].pdst
                    break
            elif IP in packet:
                if packet[IP].src == ip:
                    ip_info["MAC"] = packet[Ether].src
                    break

        for packet in self.pcap:
            if IP in packet and packet[IP].src == ip:
                ip_info["IP VERSION"] = packet[IP].version
                break

        for packet in self.pcap:
            if IP in packet and packet[IP].src == ip:
                ip_info["TTL"] = packet[IP].ttl
                break

        return ip_info


    def guess_os(self, device_info):
        """
        returns assumed operating system of a device
        """

        if "TTL" in device_info:
            if device_info["TTL"] in LINUX_TTL:
                return "LINUX"

            if device_info["TTL"] in WINDOWS_TTL:
                return "WINDOWS"
        elif "BROADCAST MAC" in device_info:
            if device_info["BROADCAST MAC"] == LINUX_BROADCAST_MAC:
                return "LINUX"

            if device_info["BROADCAST MAC"] == WINDOWS_BROADCAST_MAC:
                return "WINDOWS"

        return "Unknown"


    def get_info(self):
        """
        returns a list of dicts with information about every device in the pcap
        """

        info = []
        for mac in self.get_macs():
            mac_info = self.get_info_by_mac(mac)
            mac_info["OS"] = self.guess_os(mac_info)
            info.append(mac_info)
        for ip in self.get_ips():
            ip_info = self.get_info_by_ip(ip)
            ip_info["OS"] = self.guess_os(ip_info)
            info.append(ip_info)

        return info


    def __repr__(self):
        return repr(self.pcap)


    def __str__(self):
        return str(self.pcap)


if __name__ == '__main__':
    print("\n".join([str(d) for d in AnalyzeNetwork("pcap-02.pcapng").get_info()]))
