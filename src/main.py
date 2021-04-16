import sys
import os
import subprocess
import ipaddress
import threading
import nmap

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
        self.setFixedSize(900, 850)
        self.setWindowIcon(QtGui.QIcon(icon_window))
        # self.actionVersion.setText(f'Versie v{current_version}')
        self.pb_start_nwscan.clicked.connect(self.start_nwscan)
        self.lb_error_ip.setHidden(True)
        self.lb_error_endip.setHidden(True)
        self.lb_error_ip.setStyleSheet("color: red")
        self.lb_error_endip.setStyleSheet("color: red")
        self.lb_error_ip.setText("Enter a valid IP-address")
        self.lb_error_endip.setText("Enter a number between 1 and 254")

        for nic in get_networkcards():
            self.combo_networkcard.addItem(nic)

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
        ip_address = ""
        end_ip = ""
        if self.valid_ip():
            ip_address = self.line_ipaddress.text()
        elif self.valid_endip():
            end_ip = self.line_end_ip.text()
        else:
            # NMAP variables IP-address End IP-address and networkcard
            ip_range = f'{ip_address}-{end_ip}'
            scan = nm.scan(hosts=ip_range, arguments='sn')
            print('Scan started....')
            print(scan)

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



