#!/usr/bin/env python3

import nmap

scanner = nmap.PortScanner()


def stealth_scan():
	scanner.scan("192.168.0.137", '1-1024', '-v -SS')
	print(scanner.scaninfo())


print(scanner.nmap_version())

stealth_scan()
stealth_scan()
