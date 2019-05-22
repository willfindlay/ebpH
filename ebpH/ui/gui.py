#! /usr/bin/env python3

import sys
import textwrap
from PySide2.QtGui import *
from PySide2.QtWidgets import *
from PySide2.QtCore import *
from mainwindow import Ui_MainWindow

# to recompile UI or Resources files, just run make

class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.setupUi(self)
        self.connect_slots()
        self.showMaximized()

    # --- Initialization Helpers ---

    def connect_slots(self):
        # --- File Menu ---
        self.action_Force_Save_Profiles
        self.actionExport_Logs
        self.actionExport_Statistics
        # quit is implicit in the .ui file

        # --- Monitoring Menu ---
        self.action_Start_Monitoring
        self.action_Stop_Monitoring
        # this is bound to the "View/Modify Profile" button in the menu
        self.action_Inspect_Executable

        # --- Settings Menu ---
        self.action_Preferences

        # --- Help Menu ---
        self.actionebpH_Help.triggered.connect(self.show_ebpH_help)
        self.action_About.triggered.connect(self.about_ebpH)

    # --- Slots ---

    def show_ebpH_help(self):
        text = """
        """
        self.info_box(text)

    def about_ebpH(self):
        text = """
        ebpH -- Monitor syscall sequences and detect anomalies
        Copyright 2019 Anil Somayaji (soma@scs.carleton.ca) and
        William Findlay (williamfindlay@cmail.carleton.ca)

        Based on Sasha Goldshtein's syscount
            https://github.com/iovisor/bcc/blob/master/tools/syscount.py
            Copyright 2017, Sasha Goldshtein.
        And on Anil Somayaji's pH
            http://people.scs.carleton.ca/~mvvelzen/pH/pH.html
            Copyright 2003 Anil Somayaji

        USAGE: ebpH.py

        Licensed under GPL v2 License
        """
        self.info_box(text)

    # --- Generic Helpers ---

    def info_box(self, text, title="Information"):
        text = textwrap.dedent(text)
        QMessageBox.information(self, title, text)

# --- Main Control Flow ---
if __name__ == '__main__':
     app = QApplication(sys.argv)
     mainWin = MainWindow()
     ret = app.exec_()
     sys.exit(ret)
