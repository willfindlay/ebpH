# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'saveprogress.ui',
# licensing of 'saveprogress.ui' applies.
#
# Created: Sat Jun  1 13:34:28 2019
#      by: pyside2-uic  running on PySide2 5.12.0
#
# WARNING! All changes made in this file will be lost!

from PySide2 import QtCore, QtGui, QtWidgets

class Ui_SaveProgress(object):
    def setupUi(self, SaveProgress):
        SaveProgress.setObjectName("SaveProgress")
        SaveProgress.resize(400, 300)
        self.gridLayout = QtWidgets.QGridLayout(SaveProgress)
        self.gridLayout.setObjectName("gridLayout")
        self.label = QtWidgets.QLabel(SaveProgress)
        self.label.setObjectName("label")
        self.gridLayout.addWidget(self.label, 0, 0, 1, 1)
        spacerItem = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout.addItem(spacerItem, 1, 0, 1, 1)
        self.save_progress = QtWidgets.QProgressBar(SaveProgress)
        self.save_progress.setProperty("value", 0)
        self.save_progress.setObjectName("save_progress")
        self.gridLayout.addWidget(self.save_progress, 2, 0, 1, 1)

        self.retranslateUi(SaveProgress)
        QtCore.QMetaObject.connectSlotsByName(SaveProgress)

    def retranslateUi(self, SaveProgress):
        SaveProgress.setWindowTitle(QtWidgets.QApplication.translate("SaveProgress", "Dialog", None, -1))
        self.label.setText(QtWidgets.QApplication.translate("SaveProgress", "Saving profiles...", None, -1))

