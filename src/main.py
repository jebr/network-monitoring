import sys
import os
import subprocess
import ipaddress
import threading
import nmap
import pprint

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
icon_window = ""

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
        self.lb_error_ip.setHidden(True)
        self.lb_error_endip.setHidden(True)
        self.lb_error_ip_ps.setHidden(True)
        self.lb_error_custom_port.setHidden(True)
        self.lb_error_ip.setStyleSheet("color: red")
        self.lb_error_endip.setStyleSheet("color: red")
        self.lb_error_ip_ps.setStyleSheet("color: red")
        self.lb_error_custom_port.setStyleSheet("color: red")
        self.lb_error_ip.setText("Enter a valid IP-address")
        self.lb_error_endip.setText("Enter a number between 1 and 254")
        self.lb_error_ip_ps.setText("Enter a valid IP-address")
        self.lb_error_custom_port.setText("Enter a number between 1 and 254")
        self.table_networkscan.setColumnCount(3)
        self.table_networkscan.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table_networkscan.setHorizontalHeaderLabels(["IP-address", "Up/Down", "Hostname"])
        self.rb_20.toggled.connect(self.disable_custom_port_line)
        self.rb_1000.toggled.connect(self.disable_custom_port_line)
        self.rb_custom.toggled.connect(self.enable_custom_port_line)

        for nic in get_networkcards():
            self.combo_networkcard.addItem(nic)

    def disable_custom_port_line(self):
        self.line_custom_port.setEnabled(False)

    def enable_custom_port_line(self):
        self.line_custom_port.setEnabled(True)

    def valid_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.line_ipaddress.text())
            return True
        except:
            self.lb_error_ip.setHidden(False)
            start_time = threading.Timer(3, self.hide_error_messages)
            start_time.start()
            return False

    def valid_endip(self) -> bool:
        try:
            int(self.line_end_ip.text())
            ip = int(self.line_end_ip.text())
            if 0 < ip <= 254:
                return True
        except:
            self.lb_error_endip.setHidden(False)
            start_time = threading.Timer(3, self.hide_error_messages)
            start_time.start()
            return False

    def start_nwscan(self):
        if self.valid_ip() and self.valid_endip():
            ip_address = self.line_ipaddress.text()
            end_ip = self.line_end_ip.text()
            net_card = self.combo_networkcard.currentText()
            # NMAP variables IP-address End IP-address and networkcard
            ip_range = f'{ip_address}-{end_ip}'
            print('Scan started....')

            nm.scan(hosts=ip_range, arguments='-sn')
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
            # self.table_networkscan.resizeColumnsToContents()
            # self.table_networkscan.setStretchLastSection(True)
            self.table_networkscan.setRowCount(len(ip_list))
            for item in range(len(ip_list)):
                # print(f'{item}: {ip_list[item]}')
                self.table_networkscan.setItem(row_number, 0, QTableWidgetItem(ip_list[item][0]))
                self.table_networkscan.setItem(row_number, 1, QTableWidgetItem(ip_list[item][1]))
                self.table_networkscan.setItem(row_number, 2, QTableWidgetItem(hosts[item]))
                row_number += 1
            print('Scan finished')

    def start_pscan(self):
        print("Port scan started...")

        print("Port scan finished")



    def hide_error_messages(self):
        self.lb_error_ip.setHidden(True)
        self.lb_error_endip.setHidden(True)



def main():
    app = QApplication(sys.argv)
    widget = MainPage()
    widget.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()



