#!/usr/bin/env python3
import sys
import os
import ipaddress
import nmap
import netifaces
import datetime
import functools
import threading


# PyQT modules
from PyQt5.QtCore import QDateTime
from PyQt5.QtGui import QPixmap, QIcon
from PyQt5.QtWidgets import QApplication, QDialog, QFileDialog, QMessageBox, \
    QTableWidgetItem, QLabel, QTabWidget
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets, QtGui, QtCore

from icmplib import ICMPv4Socket, ICMPv6Socket, ICMPRequest, ICMPReply


# Resource path bepalen
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.environ.get("_MEIPASS2", os.path.abspath("."))
    # logging.info('Pyinstaller file location {}'.format(base_path))
    return os.path.join(base_path, relative_path)


def thread(func):
    @functools.wraps(func)
    def wrapper(self, **kwargs):
        if 'daemon' in kwargs:
            daemon = kwargs.pop('daemon')
        else:
            daemon = True
        t = threading.Thread(target=func, args=[self], daemon=daemon)
        t.start()

    return wrapper

# External files
ui_main_window = resource_path('resources/ui/main.ui')
ui_top20_window = resource_path('resources/ui/20_known_ports.ui')
ui_top100_window = resource_path('resources/ui/100_known_ports.ui')
icon_window = resource_path('icons/network-icon.ico')
icon_circle_info = resource_path('icons/circle-info.png')
comming_soon_img = resource_path('icons/comming-soon.jpg')

# Software version
current_version = float(1.0)


class BaseWindow:
    # Messageboxen
    def infobox(self, message):
        QMessageBox.information(self, 'Info', message, QMessageBox.Ok)

    def warningbox(self, message):
        QMessageBox.warning(self, 'Warning', message, QMessageBox.Close)

    def criticalbox(self, message):
        QMessageBox.critical(self, 'Error', message, QMessageBox.Close)

    def question(self, message):
        QMessageBox.question(self, 'Question', message, QMessageBox.Ok)

    def noicon(self, message):
        QMessageBox.noicon(self, '', message, QMessageBox.Ok)


def get_networkcards() -> list:
    nics = netifaces.interfaces()
    return nics


def valid_ip(ip) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except:
        return False


def valid_endip(endip) -> bool:
    try:
        number = int(endip)
        if 0 < number <= 254:
            return True
    except:
        return False


def valid_port_list(ports) -> bool:
    # Regex om de input te controleren
    pattern = re.compile(r'[\d,-]+')
    # Check op fullmatch met pattern
    matches = pattern.fullmatch(ports)
    if matches:
        return True
    else:
        return False


def state_scan(ip) -> bool:
    try:
        nm = nmap.PortScanner()
        scan = nm.scan(hosts=ip, arguments='-sn')
        down = scan['nmap']['scanstats']['downhosts']
        if down == '1':
            return False
        else:
            return True
    except Exception:
        return False


stop_ping = False


class MainPage(QtWidgets.QMainWindow, BaseWindow):
    def __init__(self):
        super().__init__()
        loadUi(ui_main_window, self)
        self.setFixedSize(640, 480)
        self.setWindowIcon(QtGui.QIcon(icon_window))
        # self.actionVersion.setText(f'Versie v{current_version}')
        self.setWindowTitle("Network Monitoring")
        # Portscan elements
        self.pb_start_nwscan.clicked.connect(self.start_nwscan)
        self.pb_start_pscan.clicked.connect(self.start_pscan)
        # Table elements
        self.table_networkscan.setColumnCount(3)
        self.table_portscan.setColumnCount(3)
        self.table_networkscan.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table_portscan.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table_networkscan.setHorizontalHeaderLabels(["IP-address", "Up/Down", "Hostname"])
        self.table_portscan.setHorizontalHeaderLabels(["Port", "State", "Service Name"])
        # Networkscan elements
        self.rb_20.toggled.connect(self.disable_custom_port_line)
        self.rb_100.toggled.connect(self.disable_custom_port_line)
        self.rb_custom.toggled.connect(self.enable_custom_port_line)
        self.pb_known_20.clicked.connect(self.open_top20_window)
        self.pb_known_100.clicked.connect(self.open_top100_window)
        self.pb_known_20.setIcon(QIcon(QPixmap(icon_circle_info)))
        self.pb_known_100.setIcon(QIcon(QPixmap(icon_circle_info)))
        # Ping detector
        self.ping_listen_button_start.clicked.connect(self.start_ping_scan)
        self.ping_listen_button_stop.clicked.connect(self.stop_ping_scan)
        self.ping_results_table.setColumnCount(3)
        self.ping_results_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.ping_results_table.setHorizontalHeaderLabels(["Source", "ICMP Type", "Time"])
        self.ping_listen_button_stop.setEnabled(False)

        for nic in get_networkcards():
            self.combo_networkcard.addItem(nic)

        self.combo_networkcard.currentIndexChanged.connect(self.get_network_data)

        # Define Nmap
        try:
            nm = nmap.PortScanner()
        except:
            sys.exit(self.criticalbox("To use this application NMAP is required!\n\n"
                                      "sudo apt install nmap -yy"))

    def stop_ping_scan(self):
        global stop_ping
        stop_ping = True
        self.ping_listen_button_stop.setEnabled(False)
        self.ping_listen_button_start.setEnabled(True)
        return stop_ping

    def start_ping_scan(self):
        # Check if we are root, because opening sockets is going to require root
        if not os.geteuid() == 0:
            self.criticalbox("\nOnly root can run listen for ICMP packets.\n"
                             "Restart the application with root privileges")
        else:
            self.ping_scan()

    @thread
    def ping_scan(self):
        global stop_ping
        stop_ping = False
        self.ping_listen_button_stop.setEnabled(True)
        self.ping_listen_button_start.setEnabled(False)

        # Prepare tables
        self.ping_results_table.clearContents()
        self.ping_results_table.setRowCount(0)

        row = 0
        sock = ICMPv4Socket()

        while True:
            reply = sock.receive(None, 2000)

            date = datetime.datetime.fromtimestamp(int(reply.time))

            # Add listen entry to table
            self.ping_results_table.insertRow(row)
            self.ping_results_table.setItem(row, 0, QTableWidgetItem(reply.source))
            self.ping_results_table.setItem(row, 1, QTableWidgetItem(self.lookup_icmp_type(reply.type)))
            self.ping_results_table.setItem(row, 2, QTableWidgetItem(str(date)))

            if stop_ping:
                break

            row += 1

    # Table with all non-deprecated and non-reserved ICMP types
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
    def lookup_icmp_type(self, icmp_type):
        types = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            5: "Redirect",
            8: "Echo",
            9: "Router Advertisement",
            10: "Router Selection",
            11: "Time Exceeded",
            12: "Parameter Problem",
            13: "Timestamp",
            14: "Timestamp Reply",
            40: "Photuris",
            42: "Extended Echo Request",
            43: "Extended Echo Reply"
        }

        if int(icmp_type) in types:
            return types[int(icmp_type)]
        else:
            return "Unknown ICMP type (" + str(icmp_type) + ")"

    def get_network_data(self):
        self.list_network_data.clear()
        nic = self.combo_networkcard.currentText()
        data = netifaces.ifaddresses(nic)
        gateways = netifaces.gateways()
        self.list_network_data.addItem(f'IP address: {data[netifaces.AF_INET][0]["addr"]}')
        self.list_network_data.addItem(f'IP Netmask: {data[netifaces.AF_INET][0]["netmask"]}')
        self.list_network_data.addItem(f'Default gateway: {gateways["default"][netifaces.AF_INET][0]} '
                                       f'({gateways["default"][netifaces.AF_INET][1]})')

    def disable_custom_port_line(self):
        self.line_custom_port.setEnabled(False)

    def enable_custom_port_line(self):
        self.line_custom_port.setEnabled(True)

    def start_nwscan(self):
        nm = nmap.PortScanner()
        if not valid_ip(self.line_ipaddress.text()):
            self.criticalbox('Enter a valid IP address')

        if not valid_endip(self.line_end_ip.text()):
            self.criticalbox('Enter a number between 1 and 254')

        # Tabel leeg maken voor een nieuwe scan
        self.table_networkscan.clearContents()
        self.table_networkscan.setRowCount(0)
        scan = {}

        if valid_ip(self.line_ipaddress.text()) and valid_endip(self.line_end_ip.text()):
            self.infobox('Network scan started...')
            ip_address = self.line_ipaddress.text()
            end_ip = self.line_end_ip.text()
            # NMAP variables IP-address End IP-address and networkcard
            ip_range = f'{ip_address}-{end_ip}'
            try:
                nm.scan(hosts=ip_range, arguments=f'-sn')
            except Exception:
                self.criticalbox('An unexpected error has occurred')
            all_hosts = nm.all_hosts()
            # Maak een lijst van devices met de status en state waarde uit de dictionary
            ip_list = [[host, nm[host]['status']['state']] for host in all_hosts]
            # Maak een lijst van devices met de hostnames en name waarde uit de dictionary
            host_list = [[host, nm[host]['hostnames']] for host in all_hosts]
            # Haal de dictionary met name en PTR uit de host_list en zet deze in een nieuwe lijst
            hostnames = [host[1][0] for host in host_list]
            hosts = []
            # Haal de waarde van de name uit de dictionary
            for host_dict in hostnames:
                for key, value in host_dict.items():
                    if key == 'name':
                        hosts.append(value)

            #  Vullen van de tabel
            row_number = 0
            self.table_networkscan.setRowCount(len(ip_list))
            for item in range(len(ip_list)):
                self.table_networkscan.setItem(row_number, 0, QTableWidgetItem(ip_list[item][0]))
                self.table_networkscan.setItem(row_number, 1, QTableWidgetItem(ip_list[item][1]))
                self.table_networkscan.setItem(row_number, 2, QTableWidgetItem(hosts[item]))
                row_number += 1
            self.infobox('Network scan finished')

    def start_pscan(self):
        nm = nmap.PortScanner()
        temp_port_list = []
        ports_list = []
        custom_ports = ""
        ports_are_valid = False
        ports = self.line_custom_port.text()
        counter = 0

        if not valid_ip(self.line_ip_address_ps.text()):
            self.criticalbox('Enter a valid IP address')

        if not valid_port_list(ports) and self.rb_custom.isChecked():
            self.criticalbox('Invalid input\ne.g. 80,80,21\ne.g. 8080-8085')

        if not self.rb_custom.isChecked():
            ports_are_valid = True

        # Controleer of de match True is
        if valid_port_list(ports):
            # Controleer of de poortlijst een - of , bevat
            if '-' in ports and ',' in ports:
                ports_are_valid = False
                self.criticalbox('Invalid input\ne.g. 80,80,21\ne.g. 8080-8085')
            elif ',' in ports:
                ports_are_valid = True
                temp_port_list = ports.split(",")
            elif '-' in ports:
                for i in ports:
                    if i == "-":
                        counter += 1
                if counter > 1:
                    ports_are_valid = False
                    self.criticalbox('Invalid input\ne.g. 80,80,21\ne.g. 8080-8085')
                else:
                    ports_are_valid = True
                    ports_list = ports.split("-")
            else:
                ports_are_valid = True
                temp_port_list.append(ports)

            # Controleer of de ingevoerde waarde tussen 1 en 65535 is
            for i in ports_list:
                if (int(i) < 1) or (int(i) > 65535):
                    self.criticalbox("Port not valid\nPort value between 1 and 65535")
                    ports_are_valid = False
                    break

            if "-" not in ports:
                # Verwijder lege items uit de lijst
                for port in temp_port_list:
                    if port == "":
                        continue
                    else:
                        ports_list.append(port)
                # Maak van de lijst een string om deze te kunnen gebruiken in de portscan
                custom_ports = ','.join(ports_list)
            else:
                custom_ports = ports

        if self.rb_20.isChecked():
            ports = '--top-ports 20'
        # Port scan boven de 30 geeft geen output op gesloten poorten
        if self.rb_100.isChecked():
            ports = '--top-ports 100'
        if self.rb_custom.isChecked():
            ports = f'-p {custom_ports}'

        # Tabel leeg maken voor een nieuwe scan
        self.table_portscan.clearContents()
        self.table_portscan.setRowCount(0)
        scan = {}

        if valid_ip(self.line_ip_address_ps.text()) and ports_are_valid:
            if not state_scan(self.line_ip_address_ps.text()):
                self.criticalbox('The host appears to be offline')
            else:
                self.infobox('Port scan started...')
                ip_address = self.line_ip_address_ps.text()
                try:
                    scan = nm.scan(hosts=ip_address, arguments=f'-Pn {ports}')
                except Exception:
                    self.criticalbox('An unexpected error has occurred')

                scanned_ports = []
                port_list = []
                # Maak een lijst van devices met de gescande porten en name waarde uit de dictionary
                try:
                    port_list = [scan['scan'][ip_address]['tcp']]
                    # Maak een lijst aan met alle gescande poorten
                    for port_list_dict in port_list:
                        for key, value in port_list_dict.items():
                            scanned_ports.append(key)
                except:
                    scanned_ports = []

                # Vullen van de tabel
                row_number = 0
                # self.table_portscan.setRowCount(len(scanned_ports))
                for port in scanned_ports:
                    if port_list[0][port]['state'] == "filtered" or port_list[0][port]['state'] == "closed":
                        continue
                    else:
                        self.table_portscan.insertRow(row_number)
                        self.table_portscan.setItem(row_number, 1, QTableWidgetItem(port_list[0][port]['state']))
                    self.table_portscan.setItem(row_number, 0, QTableWidgetItem(str(port)))
                    self.table_portscan.setItem(row_number, 2, QTableWidgetItem(port_list[0][port]['name']))
                    row_number += 1
                self.infobox('Port scan finished')

    def open_top20_window(self):
        info_window_ = Top20Window()
        info_window_.exec_()

    def open_top100_window(self):
        info_window_ = Top100Window()
        info_window_.exec_()


class Top20Window(QDialog):
    def __init__(self):
        super().__init__(None, QtCore.Qt.WindowCloseButtonHint)
        self.setFixedSize(240, 320)
        loadUi(ui_top20_window, self)
        self.setWindowIcon(QtGui.QIcon(icon_window))


class Top100Window(QDialog):
    def __init__(self):
        super().__init__(None, QtCore.Qt.WindowCloseButtonHint)
        self.setFixedSize(240, 320)
        loadUi(ui_top100_window, self)
        self.setWindowIcon(QtGui.QIcon(icon_window))


def main():
    app = QApplication(sys.argv)
    widget = MainPage()
    widget.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()




