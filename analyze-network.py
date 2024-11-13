from scapy.all import rdpcap
from scapy.layers.l2 import Ether, ARP
from mac_vendor_lookup import MacLookup


SPECIAL_MACS = ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")

MAC_INFO = {"MAC": "Unknown", "IP": "Unknown", "VENDOR": "Unknown"}
IP_INFO = {"IP": "Unknown", "MAC": "Unknown"}

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

        return ip_info


    def get_info(self):
        """
        returns a list of dicts with information about every device in the pcap
        """

        info = []
        for mac in self.get_macs():
            info.append(self.get_info_by_mac(mac))

        return info


    def __repr__(self):
        return repr(self.pcap)


    def __str__(self):
        return str(self.pcap)


if __name__ == '__main__':
    print("\n".join([str(d) for d in AnalyzeNetwork("pcap-00.pcapng").get_info()]))
