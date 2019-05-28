# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'profiledialog.ui',
# licensing of 'profiledialog.ui' applies.
#
# Created: Mon May 27 20:34:52 2019
#      by: pyside2-uic  running on PySide2 5.12.0
#
# WARNING! All changes made in this file will be lost!

from PySide2 import QtCore, QtGui, QtWidgets

class Ui_ProfileDialog(object):
    def setupUi(self, ProfileDialog):
        ProfileDialog.setObjectName("ProfileDialog")
        ProfileDialog.resize(941, 803)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(":/img/assets/img/icons/browser.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        ProfileDialog.setWindowIcon(icon)
        self.gridLayout = QtWidgets.QGridLayout(ProfileDialog)
        self.gridLayout.setObjectName("gridLayout")
        self.gridLayout_2 = QtWidgets.QGridLayout()
        self.gridLayout_2.setContentsMargins(-1, 0, -1, -1)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.gridLayout_3 = QtWidgets.QGridLayout()
        self.gridLayout_3.setObjectName("gridLayout_3")
        self.lineEdit = QtWidgets.QLineEdit(ProfileDialog)
        self.lineEdit.setObjectName("lineEdit")
        self.gridLayout_3.addWidget(self.lineEdit, 0, 1, 1, 1)
        self.label_3 = QtWidgets.QLabel(ProfileDialog)
        self.label_3.setObjectName("label_3")
        self.gridLayout_3.addWidget(self.label_3, 0, 0, 1, 1)
        spacerItem = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.gridLayout_3.addItem(spacerItem, 3, 0, 1, 1)
        self.label_4 = QtWidgets.QLabel(ProfileDialog)
        self.label_4.setObjectName("label_4")
        self.gridLayout_3.addWidget(self.label_4, 1, 0, 1, 1)
        self.lineEdit_2 = QtWidgets.QLineEdit(ProfileDialog)
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.gridLayout_3.addWidget(self.lineEdit_2, 1, 1, 1, 1)
        self.syscalls = QtWidgets.QListWidget(ProfileDialog)
        self.syscalls.setObjectName("syscalls")
        self.gridLayout_3.addWidget(self.syscalls, 2, 1, 1, 1)
        self.label_5 = QtWidgets.QLabel(ProfileDialog)
        self.label_5.setObjectName("label_5")
        self.gridLayout_3.addWidget(self.label_5, 2, 0, 1, 1)
        self.gridLayout_2.addLayout(self.gridLayout_3, 1, 1, 1, 1)
        self.label_2 = QtWidgets.QLabel(ProfileDialog)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(3)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label_2.sizePolicy().hasHeightForWidth())
        self.label_2.setSizePolicy(sizePolicy)
        self.label_2.setObjectName("label_2")
        self.gridLayout_2.addWidget(self.label_2, 0, 1, 1, 1)
        self.profile_list = QtWidgets.QListWidget(ProfileDialog)
        self.profile_list.setObjectName("profile_list")
        self.gridLayout_2.addWidget(self.profile_list, 1, 0, 1, 1)
        self.label = QtWidgets.QLabel(ProfileDialog)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(1)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label.sizePolicy().hasHeightForWidth())
        self.label.setSizePolicy(sizePolicy)
        self.label.setObjectName("label")
        self.gridLayout_2.addWidget(self.label, 0, 0, 1, 1)
        self.refresh_button = QtWidgets.QPushButton(ProfileDialog)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.refresh_button.sizePolicy().hasHeightForWidth())
        self.refresh_button.setSizePolicy(sizePolicy)
        self.refresh_button.setText("")
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(":/img/assets/img/icons/redo.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.refresh_button.setIcon(icon1)
        self.refresh_button.setDefault(False)
        self.refresh_button.setFlat(True)
        self.refresh_button.setObjectName("refresh_button")
        self.gridLayout_2.addWidget(self.refresh_button, 0, 2, 1, 1)
        self.gridLayout.addLayout(self.gridLayout_2, 0, 0, 1, 1)
        self.buttonBox = QtWidgets.QDialogButtonBox(ProfileDialog)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.gridLayout.addWidget(self.buttonBox, 1, 0, 1, 1)

        self.retranslateUi(ProfileDialog)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL("accepted()"), ProfileDialog.accept)
        QtCore.QObject.connect(self.buttonBox, QtCore.SIGNAL("rejected()"), ProfileDialog.reject)
        QtCore.QMetaObject.connectSlotsByName(ProfileDialog)

    def retranslateUi(self, ProfileDialog):
        ProfileDialog.setWindowTitle(QtWidgets.QApplication.translate("ProfileDialog", "View/Modify Profiles", None, -1))
        self.label_3.setText(QtWidgets.QApplication.translate("ProfileDialog", "Comm", None, -1))
        self.label_4.setText(QtWidgets.QApplication.translate("ProfileDialog", "Anomalies", None, -1))
        self.label_5.setText(QtWidgets.QApplication.translate("ProfileDialog", "Recent\n"
"System Calls", None, -1))
        self.label_2.setText(QtWidgets.QApplication.translate("ProfileDialog", "Details", None, -1))
        self.label.setText(QtWidgets.QApplication.translate("ProfileDialog", "Profiles", None, -1))
        self.refresh_button.setToolTip(QtWidgets.QApplication.translate("ProfileDialog", "Refresh", None, -1))

import resources_rc
