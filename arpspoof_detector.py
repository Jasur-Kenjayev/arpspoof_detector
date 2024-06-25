import scapy.all as scapy

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcas = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcas = broadcas / arp_request
    answared_list = scapy.srp(arp_request_broadcas, timeout=1, verbose=False)[0]
    return answared_list[0][1].hwsrc

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffe_packet)

def process_sniffe_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc

            if real_mac != response_mac:
                print("[+] You are under attack!!!")
        except IndexError:
            pass


sniff("eth0")