#! /usr/bin/env python3

# ebpH --  Monitor syscall sequences and detect anomalies
# Copyright 2019 Anil Somayaji (soma@scs.carleton.ca) and
# William Findlay (williamfindlay@cmail.carleton.ca)
#
# Based on Sasha Goldshtein's syscount
#  https://github.com/iovisor/bcc/blob/master/tools/syscount.py
#  Copyright 2017, Sasha Goldshtein.
# And on Anil Somayaji's pH
#  http://people.scs.carleton.ca/~mvvelzen/pH/pH.html
#  Copyright 2003 Anil Somayaji
#
# USAGE: ebpH.py <COMMAND>
#
# Licensed under GPL v2 License

import sys
import os
import textwrap
from pprint import pprint
from PySide2.QtGui import *
from PySide2.QtWidgets import *
from PySide2.QtCore import *
from mainwindow import Ui_MainWindow
from bpf_thread import BPFThread

# to recompile UI or Resources files, just run make

class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.setupUi(self)
        self.connect_slots()
        self.showMaximized()
        self.bpf_thread = BPFThread()
        self.monitoring = False

    # --- Initialization Helpers ---

    def connect_slots(self):
        # --- File Menu ---
        self.action_Force_Save_Profiles
        self.actionExport_Logs
        self.actionExport_Statistics
        # quit is implicit in the .ui file

        # --- Monitoring Menu ---
        self.action_Start_Monitoring.triggered.connect(self.toggle_monitoring)
        self.action_Stop_Monitoring.triggered.connect(self.toggle_monitoring)
        # this is bound to the "View/Modify Profile" button in the menu
        self.action_View_Modify_Profile

        # --- Settings Menu ---
        self.action_Preferences

        # --- Help Menu ---
        self.actionebpH_Help.triggered.connect(self.show_ebpH_help)
        self.action_About.triggered.connect(self.about_ebpH)

    # --- Slots ---

    def show_ebpH_help(self):
        text = """
        A help message will go here.
        """
        self.info_box(text)

    def about_ebpH(self):
        text = """\
        ebpH -- Monitor syscall sequences and detect anomalies
        Copyright 2019 Anil Somayaji (soma@scs.carleton.ca) and
        William Findlay (williamfindlay@cmail.carleton.ca)

        Based on <a href='https://github.com/iovisor/bcc/blob/master/tools/syscount.py'>Sasha Goldshtein's syscount</a>
          Copyright 2017, Sasha Goldshtein.
        And on <a href='http://people.scs.carleton.ca/~mvvelzen/pH/pH.html'>Anil Somayaji's pH</a>
          Copyright 2003 Anil Somayaji

        USAGE: ebpH.py

        Licensed under GPL v2
        """
        self.info_box(text)

    def toggle_monitoring(self):
        self.monitoring = not self.monitoring
        if self.monitoring:
            self.action_Start_Monitoring.setEnabled(False)
            self.action_Stop_Monitoring.setEnabled(True)
            self.bpf_thread.start()
        else:
            self.action_Start_Monitoring.setEnabled(True)
            self.action_Stop_Monitoring.setEnabled(False)
            self.bpf_thread.exiting = True

    # --- Generic Helpers ---

    def info_box(self, text, title="Information"):
        text = textwrap.dedent(text)
        text = text.replace("\n","<br>")
        b = QMessageBox(self)
        b.setWindowTitle(title)
        b.setText(text)
        b.setIcon(QMessageBox.Information)
        b.setTextFormat(Qt.RichText)
        b.exec_()

# --- Main Control Flow ---
if __name__ == '__main__':
    # check privileges
    if not ('SUDO_USER' in os.environ and os.geteuid() == 0):
        print("This script must be run with root privileges! Exiting.")
        sys.exit(-1)
    app = QApplication(sys.argv)
    mainWin = MainWindow()
    ret = app.exec_()
    sys.exit(ret)
