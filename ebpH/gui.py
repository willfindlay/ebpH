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
import re
import textwrap
import datetime
import atexit
from time import sleep
from pprint import pprint
from PySide2.QtGui import *
from PySide2.QtWidgets import *
from PySide2.QtCore import *
from PySide2.QtCharts import *
from mainwindow import Ui_MainWindow
from profiledialog import Ui_ProfileDialog
from bpf_thread import BPFThread

# directory in which profiles are stored
PROFILE_DIR = "/var/lib/pH/profiles"
# path of profile loader executable
LOADER_PATH = os.path.abspath("profile_loader")

# --- HTML Color Definitions ---

def color(color):
    return "".join(["<font color=\"", color, "\">"])

ORANGE = color("#ff6600")
BLACK  = color("#000000")
GREEN  = color("#009900")
RED    = color("#990000")
BLUE   = color("#000099")

# --- Profile Dialog ---

class ProfileDialog(QDialog, Ui_ProfileDialog):
    def __init__(self, parent=None):
        super(ProfileDialog, self).__init__(parent)
        self.setupUi(self)
        self.update_list()
        self.refresh_button.pressed.connect(self.refresh)

    def update_list(self):
        filenames = os.listdir(PROFILE_DIR)
        items = [filename for filename in filenames]
        self.profile_list.addItems(items)

    def refresh(self):
        print("refresh pressed")
        self.update_list()

# --- Main Window ---

# to recompile UI or Resources files, just run make

class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.setupUi(self)
        self.monitoring = False
        self.can_exit = True

        # setup thread
        self.bpf_thread = BPFThread(self)

        # add graph
        self.series = QtCharts.QLineSeries()
        self.chart_view = QtCharts.QChartView()
        self.chart_view.chart().addSeries(self.series)
        self.chart_view.chart().createDefaultAxes()
        self.chart_view.chart().layout().setContentsMargins(0, 0, 0, 0);
        self.chart_view.chart().setBackgroundRoundness(0);
        #self.chart_view.chart().setTitle("ebpH Statistics Over Time")
        ell = QGridLayout()
        self.chart_container.setLayout(ell)
        self.chart_container.layout().addWidget(self.chart_view)

        # connect slots and draw window
        self.connect_slots()
        self.showMaximized()

    # --- Initialization Helpers ---

    def connect_slots(self):
        # --- File Menu ---
        self.action_Force_Save_Profiles.triggered.connect(self.bpf_thread.save_profiles)
        self.bpf_thread.sig_profiles_saved.connect(self.on_profiles_saved)
        self.actionExport_Logs.triggered.connect(self.export_logs)
        self.export_logs_button.pressed.connect(self.export_logs)
        # quit is implicit in the .ui file

        # --- Monitoring Menu ---
        self.action_Start_Monitoring.triggered.connect(self.toggle_monitoring)
        self.action_Stop_Monitoring.triggered.connect(self.toggle_monitoring)
        self.action_View_Modify_Profile.triggered.connect(self.display_profiles_dialog)

        # --- Settings Menu ---
        self.action_Preferences

        # --- Help Menu ---
        self.actionebpH_Help.triggered.connect(self.show_ebpH_help)
        self.action_About.triggered.connect(self.about_ebpH)

        # --- Log ebpH events ---
        self.bpf_thread.sig_event.connect(self.log_message)
        self.bpf_thread.sig_warning.connect(self.log_warning)
        self.bpf_thread.sig_error.connect(self.log_error)

        # --- Statistics ---
        self.bpf_thread.sig_stats.connect(self.update_stats)

        # --- Housekeeping ---
        self.bpf_thread.sig_can_exit.connect(self.update_can_exit)

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
            self.action_Force_Save_Profiles.setEnabled(True)
            self.bpf_thread.start()
            self.log("Monitoring started.", "m")
            self.monitoring_radio.setChecked(True)
            self.not_monitoring_radio.setChecked(False)
        else:
            self.bpf_thread.exiting = True
            self.action_Start_Monitoring.setEnabled(True)
            self.action_Stop_Monitoring.setEnabled(False)
            self.log("Detaching probe...", "w")
            self.monitoring_radio.setChecked(False)
            self.not_monitoring_radio.setChecked(True)
            self.action_Force_Save_Profiles.setEnabled(False)

    def log(self, event, etype="m"):
        now = datetime.datetime.now()
        time_str = now.strftime("[%m/%d/%Y %H:%M:%S]")
        event = re.sub(r"(\d+)", f"{RED}\\1{BLACK}", event)
        #event = re.sub(r"(\r\n?|\n)+", "".join(["<br>"] + ["&nbsp;" for _ in range(31)]), event)
        etype = etype.lower()
        if etype == "w":
            etype_str = "WARNING:".replace(" ","&nbsp;")
            etype_str = "".join([ORANGE, etype_str, BLACK])
        elif etype == "e":
            etype_str = "  ERROR:".replace(" ","&nbsp;")
            etype_str = "".join([RED, etype_str, BLACK])
        else:
            etype_str = "   INFO:".replace(" ","&nbsp;")
            etype_str = "".join([GREEN, etype_str, BLACK])
        self.event_log.appendHtml(" ".join([BLUE, time_str, etype_str, BLACK, event]))

    def log_message(self, event):
        self.log(event, "m")

    def log_warning(self, event):
        self.log(event, "w")

    def log_error(self, event):
        self.log(event, "e")

    def update_stats(self, profiles, syscalls, forks, execves, exits):
        self.profile_count.setText(str(profiles))
        self.syscall_count.setText(str(syscalls))
        self.fork_count.setText(str(forks))
        self.execve_count.setText(str(execves))
        self.exit_count.setText(str(exits))

    def update_can_exit(self, can_exit):
        self.can_exit = can_exit

    def on_profiles_saved(self):
        text = """
        Profiles saved successfully!
        """
        self.info_box(text=text, title="Success")

    def display_profiles_dialog(self):
        d = ProfileDialog(self)
        d.exec_()

    def export_logs(self):
        now = datetime.datetime.now()
        time_str = now.strftime("%m-%d-%Y_%H-%M-%S")
        filename, selected_filter = QFileDialog.getSaveFileName(self, "Export Logs",
                f"{os.path.expanduser('~')}/ebpH_{time_str}.log", filter="Log Files (*.log);;All Files (*)",
                selectedFilter="*.log")
        if filename:
            with open(filename,"w+") as f:
                f.write(self.event_log.toPlainText())
            os.chmod(filename, 0o666)

    # --- Event Handlers ---

    # cleanup thread before exiting
    def closeEvent(self, event):
        reply = QMessageBox.question(self, "Message", "Are you sure you want to quit?",
                QMessageBox.Yes, QMessageBox.No)
        if reply == QMessageBox.No:
            event.ignore()
            return
        self.bpf_thread.exiting = True
        self.bpf_thread.wait()
        event.accept()

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
