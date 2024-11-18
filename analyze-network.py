from scapy.all import rdpcap, Raw
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether, ARP
from mac_vendor_lookup import MacLookup


SPECIAL_MACS = ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"]
HTTP_TERMS = [b'GET', b'POST', b'HEAD', b'PUT', b'DELETE', b'CONNECT', b'OPTIONS', b'TRACE']

LINUX_TTL = range(60, 64+1)
WINDOWS_TTL = range(64+1, 128+1)
LINUX_BROADCAST_MAC = "00:00:00:00:00:00"
WINDOWS_BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
LINUX_DF = "True"
WINDOWS_DF = "False"

MAC_INFO = {"MAC": "Unknown", "IP": "Unknown", "VENDOR": "Unknown", "BROADCAST MAC": "Unknown"}
IP_INFO = {"IP": "Unknown", "MAC": "Unknown", "IP VERSION": "Unknown", "TTL": "Unknown", "DF": "Unknown", "CONNECTIONS": []}
CONNECTION = {"PROTO": "Unknown", "SIP": "Unknown", "DIP": "Unknown", "SPORT": "Unknown", "DPORT": "Unknown"}

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

        try:
            mac_info["VENDOR"] = MacLookup().lookup(mac)
        except Exception as e:
            pass

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
                ip_info["DF"] = "True" if packet[IP].flags.DF else "False"
                break

        connections = []
        sports = []
        for packet in self.pcap:
            if TCP in packet:
                if packet[IP].src == ip:
                    if packet[TCP].sport in sports:
                        if Raw in packet:
                            for term in HTTP_TERMS:
                                if term in packet[Raw].load:
                                    for connection in connections:
                                        if connection["SPORT"] == packet[TCP].sport:
                                            connection["PROTO"] = "HTTP"
                                    break

                        continue

                    connection = dict(CONNECTION)

                    connection["PROTO"] = "TCP"
                    connection["SIP"] = packet[IP].src
                    connection["DIP"] = packet[IP].dst
                    connection["SPORT"] = packet[TCP].sport
                    connection["DPORT"] = packet[TCP].dport

                    if Raw in packet:
                        for term in HTTP_TERMS:
                            if term in packet[Raw].load:
                                connection["PROTO"] = "HTTP"
                                break

                    connections.append(connection)
                    sports.append(packet[TCP].sport)
        ip_info["CONNECTIONS"] = connections

        return ip_info


    def guess_os(self, device_info):
        """
        returns assumed operating system of a device
        """
        
        if "DF" in device_info:
            if device_info["DF"] == LINUX_DF:
                return "LINUX"

            if device_info["DF"] == WINDOWS_DF:
                return "WINDOWS"
        elif "TTL" in device_info:
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

        mac_infos = []
        for mac in self.get_macs():
            mac_info = self.get_info_by_mac(mac)
            mac_info["OS"] = self.guess_os(mac_info)
            mac_infos.append(mac_info)

        ip_infos = []
        for ip in self.get_ips():
            ip_info = self.get_info_by_ip(ip)
            ip_info["OS"] = self.guess_os(ip_info)
            ip_infos.append(ip_info)

        info = []
        seen_ips = []
        for mac_info in mac_infos:
            for ip_info in ip_infos:
                if mac_info["MAC"] == ip_info["MAC"]:
                    info.append(mac_info | ip_info)
                    seen_ips.append(ip_info["IP"])
                    continue
        for ip_info in ip_infos:
            for mac_info in mac_infos:
                if ip_info["IP"] == mac_info["IP"] and ip_info["IP"] not in seen_ips:
                    info.append(mac_info | ip_info)
                    continue

        return info


    def __repr__(self):
        return repr(self.pcap)


    def __str__(self):
        return str(self.pcap)


if __name__ == '__main__':
    print("\n".join([str(d) for d in AnalyzeNetwork("pcap-02.pcapng").get_info()]))
