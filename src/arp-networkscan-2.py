# Python script to detect devices in network using Scapy

from scapy.all import arping

arping("192.168.1.0/24")