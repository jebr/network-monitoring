#!/usr/bin/env python3

import nmap

scanner = nmap.PortScanner()


def stealth_scan():
	scanner.scan("192.168.0.137", '1-1024', '-v -SS')
	print(scanner.scaninfo())


# print(scanner.nmap_version())


# scanner.scan('127.0.0.1', '21')
scanner.scan('192.168.0.202', ports="80, 443")

# print(type(scanner))

print(scanner.command_line())

print(scanner.scaninfo())

print(scanner.all_hosts())

print(scanner['127.0.0.1'].state())
# print(scanner['127.0.0.1'].all_protocols())
# print(scanner['127.0.0.1']['tcp'].keys())
# print(scanner['127.0.0.1'].has_tcp(22))
# print(scanner['127.0.0.1'].has_tcp(80))
# print(scanner['127.0.0.1'].has_tcp(22))
