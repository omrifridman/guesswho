

class AnalyzeNetwork:
    def __init__(self, pcap_path):
        """
        pcap_path (string): path to a pcap file
        """
        pass

    def get_ips(self):
        """
        returns a list of ip addresses (strings) that appear in the pcap
        """
        pass

    def get_macs(self):
        """
        returns a list of MAC addresses (strings) that appear in the pcap
        """
        pass

    def get_info_by_mac(self, mac):
        """
        returns a dict with all information about the device with given MAC address
        """
        pass

    def get_info_by_ip(self, ip):
        """
        returns a dict with all information about the device with given IP address
        """
        pass

    def get_info(self):
        """
        returns a list of dicts with information about every device in the pcap
        """
        pass

    def __repr__(self):
        pass

    def __str__(self):
        pass
