#!/usr/bin/env python3

import nmap

scanner = nmap.PortScanner()

def stealth_scan(ip_range):
	scanner.scan(ip_range, '1-1024', '-v -SS')
	print(scanner.scaninfo())


stealth_scan("192.168.0.137")