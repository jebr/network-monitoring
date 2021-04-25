import sys
import os
import subprocess
import ipaddress
import threading
import nmap
import pprint
import re

# PyQT modules
from PyQt5.QtCore import QDateTime
from PyQt5.QtGui import QPixmap, QIcon
from PyQt5.QtWidgets import QApplication, QDialog, QFileDialog, QMessageBox, \
    QTableWidgetItem, QLabel, QTabWidget
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets, QtGui, QtCore


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


# External files
ui_main_window = resource_path('resources/ui/main.ui')
icon_window = resource_path('icons/network-icon.ico')

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
    nics = subprocess.check_output(['ls', '/sys/class/net']).strip().decode()
    nics = nics.split("\n")
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
    scan = nm.scan(hosts=ip, arguments='-sn')
    down = scan['nmap']['scanstats']['downhosts']
    if down == '1':
        return False
    else:
        return True


nm = nmap.PortScanner()


class MainPage(QtWidgets.QMainWindow, BaseWindow):
    def __init__(self):
        super().__init__()
        loadUi(ui_main_window, self)
        self.setFixedSize(640, 480)
        self.setWindowIcon(QtGui.QIcon(icon_window))
        # self.actionVersion.setText(f'Versie v{current_version}')
        self.setWindowTitle("Network Monitoring")

        self.pb_start_nwscan.clicked.connect(self.start_nwscan)
        self.pb_start_pscan.clicked.connect(self.start_pscan)

        self.table_networkscan.setColumnCount(3)
        self.table_portscan.setColumnCount(3)
        self.table_networkscan.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table_portscan.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table_networkscan.setHorizontalHeaderLabels(["IP-address", "Up/Down", "Hostname"])
        self.table_portscan.setHorizontalHeaderLabels(["Port", "State", "Service Name"])
        self.rb_20.toggled.connect(self.disable_custom_port_line)
        self.rb_100.toggled.connect(self.disable_custom_port_line)
        self.rb_custom.toggled.connect(self.enable_custom_port_line)

        # for nic in get_networkcards():
        #     self.combo_networkcard.addItem(nic)

    def disable_custom_port_line(self):
        self.line_custom_port.setEnabled(False)

    def enable_custom_port_line(self):
        self.line_custom_port.setEnabled(True)

    def start_nwscan(self):
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
            nm.scan(hosts=ip_range, arguments=f'-sn')
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
        temp_port_list = []
        ports_list = []
        ports_are_valid = False
        ports = self.line_custom_port.text()

        if not valid_ip(self.line_ip_address_ps.text()):
            self.criticalbox('Enter a valid IP address')

        if not valid_port_list(ports) and self.rb_custom.isChecked():
            self.criticalbox('Invalid input\ne.g. 80,80,21\ne.g. 8080-8085')

        if not self.rb_custom.isChecked():
            ports_are_valid = True

        # Controleer of de match True is
        if valid_port_list(ports):
            ports_are_valid = True
            # Controleer of de poortlijst een - of , bevat
            if ',' in ports:
                temp_port_list = ports.split(",")
            if '-' in ports:
                temp_port_list = ports.split("-")
            else:
                temp_port_list.append(ports)
            # Verwijder lege items uit de lijst
            for port in temp_port_list:
                if port == "":
                    continue
                else:
                    ports_list.append(port)
            # Controleer of de ingevoerde waarde tussen 1 en 65535 is
            for i in ports_list:
                if (int(i) < 1) or (int(i) > 65535):
                    self.criticalbox("Port not valid\nPort value between 1 and 65535")
                    ports_are_valid = False
                    break

        # Maak van de lijst een string om deze te kunnen gebruiken in de portscan
        custom_ports = ' '.join(ports_list)

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
                scan = nm.scan(hosts=ip_address, arguments=f'-Pn {ports}')
                # Maak een lijst van devices met de gescande porten en name waarde uit de dictionary
                port_list = [scan['scan'][ip_address]['tcp']]
                # Maak een lijst aan met alle gescande poorten
                scanned_ports = []
                for port_list_dict in port_list:
                    for key, value in port_list_dict.items():
                        scanned_ports.append(key)
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


def main():
    app = QApplication(sys.argv)
    widget = MainPage()
    widget.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()



