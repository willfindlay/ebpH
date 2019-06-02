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
import ctypes as ct
from time import sleep
from pprint import pprint
from PySide2.QtGui import *
from PySide2.QtWidgets import *
from PySide2.QtCore import *
from PySide2.QtCharts import *
from mainwindow import Ui_MainWindow
from profiledialog import Ui_ProfileDialog
from saveprogress import Ui_SaveProgress
from bpf_thread import BPFThread, ProfileSaveThread
from colors import *
import globals

# directory in which profiles are stored
PROFILE_DIR = "/var/lib/pH/profiles"
# path of profile loader executable
LOADER_PATH = os.path.abspath("profile_loader")

# --- Read Chunks From File ---
# TODO: maybe remove
def read_file(filename, chunksize=8192):
    with open(filename, "rb") as f:
        while True:
            chunk = f.read(chunksize)
            if chunk:
                for b in chunk:
                    yield b
            else:
                break

# --- Profile Dialog ---

class ProfileDialog(QDialog, Ui_ProfileDialog):
    def __init__(self, parent=None):
        super(ProfileDialog, self).__init__(parent)
        self.setupUi(self)
        self.profile_list.currentItemChanged.connect(self.select_profile)
        self.reset_profile_button.pressed.connect(self.reset_profile)
        self.refresh_button.pressed.connect(self.update_list)
        self.last_selected_text = None
        self.update_list()
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.tick)
        self.update_timer.start(500)
        self.update_timer.deleteLater()

    def update_list(self):
        # attempt to remember the last selected item
        try:
            self.last_selected_text = self.profile_list.currentItem().text()
        except:
            pass

        profiles = self.parent().bpf_thread.fetch_all_profiles()

        # clear the list
        self.profile_list.clear()
        # add profiles to the list
        for payload in profiles:
            profile = payload.profile
            item = QListWidgetItem("".join([profile.comm.decode('utf-8')," (", str(profile.key), ")"]))
            # set profile key as its data for UserRole
            item.setData(Qt.UserRole, profile.key)
            self.profile_list.addItem(item)

        # sort the items
        self.profile_list.sortItems()

        # attempt to return to last selected profile
        if self.last_selected_text:
            for i in range(self.profile_list.count()):
                if self.profile_list.item(i).text() == self.last_selected_text:
                    self.profile_list.setCurrentRow(i)
                    break
        # otherwise, attempt return to position 0
        else:
            try:
                self.profile_list.setCurrentRow(0)
            except:
                pass

    # fill form with profile information
    def populate_profile_info(self):
        try:
            p = self.parent().bpf_thread.fetch_profile(self.profile_list.currentItem().data(Qt.UserRole))
        except:
            return
        if p is not None:
            self.comm.setText(p.profile.comm.decode('utf-8'))
            self.key.setText(str(p.profile.key))
            states = []
            if p.profile.frozen:
                states.append("Frozen")
            if p.profile.normal:
                states.append("Normal")
            if len(states) == 0:
                states.append("Training")
            self.state.setText("/".join(states))
            self.train_count.setText(str(p.profile.train_count))
            self.last_mod_count.setText(str(p.profile.last_mod_count))
            self.normal_count.setText(str(p.profile.normal_count))
            self.anomalies.setText(str(p.profile.anomalies))

    def select_profile(self, curr, prev):
        self.populate_profile_info()

    def tick(self):
        self.populate_profile_info()

    def reset_profile(self):
        # get the currently selected item
        selected = self.profile_list.currentItem()
        if not selected:
            return

        # ask the user if they are sure they want to reset the profile
        text = f"""
        Are you sure you want to reset the profile for {selected.text()}?
        This is not a recoverable action.
        """
        reply = QMessageBox.question(self, "Message", textwrap.dedent(text),
                QMessageBox.Yes, QMessageBox.No)
        if reply == QMessageBox.No:
            return

        # FIXME: issue a reset command with the new ebpH controller program

# --- Save Progress Dialog ---

class SaveProgressDialog(QDialog, Ui_SaveProgress):
    def __init__(self, parent=None):
        super(SaveProgressDialog, self).__init__(parent)
        self.setupUi(self)

    def update_progress(self, progress):
        self.save_progress.setValue(progress)

# --- Main Window ---

# to recompile UI or Resources files, just run make

class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.setupUi(self)
        self.monitoring = False
        self.exiting = False

        # setup thread
        self.bpf_thread = BPFThread(self)

        # add graph
        self.series = QtCharts.QLineSeries()
        self.chart_view = QtCharts.QChartView()
        self.chart_view.chart().addSeries(self.series)
        self.chart_view.chart().createDefaultAxes()
        self.chart_view.chart().layout().setContentsMargins(0, 0, 0, 0);
        self.chart_view.chart().setBackgroundRoundness(0);
        ell = QGridLayout()
        self.chart_container.setLayout(ell)
        self.chart_container.layout().addWidget(self.chart_view)

        # connect slots and draw window
        self.connect_slots()
        self.showMaximized()

    # --- Initialization Helpers ---

    def connect_slots(self):
        # --- File Menu ---
        self.action_Force_Save_Profiles.triggered.connect(self.save_profiles)
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

        # --- Profile Saving Thread ---
        self.bpf_thread.sig_save_profiles.connect(self.save_profiles)

    # --- Slots ---

    def save_profiles(self):
        dialog = SaveProgressDialog()
        self.save_thread = ProfileSaveThread(self.bpf_thread.bpf, self)
        self.save_thread.finished.connect(self.save_thread.deleteLater)
        self.save_thread.finished.connect(dialog.accept)
        self.save_thread.update_progress.connect(dialog.update_progress)
        self.save_thread.start()
        dialog.exec_()
        dialog.deleteLater()
        globals.profiles_saved.wakeAll()

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
            self.action_View_Modify_Profile.setEnabled(True)
            self.action_Force_Save_Profiles.setEnabled(True)
            self.bpf_thread.start()
            self.log("Monitoring started.", "m")
            self.monitoring_radio.setChecked(True)
            self.not_monitoring_radio.setChecked(False)
            print("----------------- attached -----------------")
        else:
            self.bpf_thread.exiting = True
            self.action_Start_Monitoring.setEnabled(True)
            self.action_Stop_Monitoring.setEnabled(False)
            self.action_View_Modify_Profile.setEnabled(False)
            self.action_Force_Save_Profiles.setEnabled(False)
            self.log("Detaching probe...", "w")
            self.monitoring_radio.setChecked(False)
            self.not_monitoring_radio.setChecked(True)
            print("----------------- detached -----------------")

    def log(self, event, etype="m"):
        now = datetime.datetime.now()
        time_str = now.strftime("[%m/%d/%Y %H:%M:%S]")
        event = re.sub(r"(\d+)", f"{RED}\\1{BLACK}", event)
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
        self.bpf_thread.closing = True
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
    globals.init()
    # check privileges
    if not ('SUDO_USER' in os.environ and os.geteuid() == 0):
        print("This script must be run with root privileges! Exiting.")
        sys.exit(-1)
    app = QApplication(sys.argv)
    mainWin = MainWindow()
    ret = app.exec_()
    sys.exit(ret)