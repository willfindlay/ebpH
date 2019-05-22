#! /usr/bin/env python3

import sys
from PySide2.QtGui import *
from PySide2.QtWidgets import *
from PySide2.QtCore import *
from mainwindow import Ui_MainWindow

class MainWindow(QMainWindow, Ui_MainWindow):
     def __init__(self):
        super(MainWindow, self).__init__()
        self.setupUi(self)
        self.connect_slots()
        self.show()

     def connect_slots(self):
        self.action_Force_Save_Profiles
        self.action_Quit
        self.action_Forget_Profile
        self.action_About
        self.action_Inspect_Executable
        self.action_Preferences
        self.action_Start_Monitoring
        self.action_Stop_Monitoring
        self.actionebpH_Help.triggered.connect(self.show_ebph_help)

     def show_ebph_help(self):
         pass

# execute app
if __name__ == '__main__':
     app = QApplication(sys.argv)
     mainWin = MainWindow()
     ret = app.exec_()
     sys.exit(ret)
