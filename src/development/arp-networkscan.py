# Python script to detect devices in network using Scapy

from scapy.all import ARP, Ether, srp
from tabulate import tabulate

# IP Address for the destination
target_ip = "192.168.0.0/24"

# create ARP packet
arp = ARP(pdst=target_ip)

# create the Ether broadcast packet
# ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
ether = Ether(dst="ff:ff:ff:ff:ff:ff")

# stack them
packet = ether/arp

result = srp(packet, timeout=3, verbose=0)[0]

# a list of clients, we will fill this in the upcoming loop
clients = []

for sent, received in result:
    # for each response, append ip and mac address to `clients` list
    clients.append({'IP-address': received.psrc, 'MAC-address': received.hwsrc})

# print clients
print("Available devices in the network:")
print(tabulate(clients, headers="keys"))

# print("IP" + " "*18+"MAC")
# for client in clients:
#     print("{:16}    {}".format(client['ip'], client['mac']))
