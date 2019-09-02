#! /usr/bin/python3

from PySide2.QtGui import *
from PySide2.QtWidgets import *
from PySide2.QtCore import *

# a lazy updating QLineEdit so the user's selection isn't being
# cancelled on each tick
class LazyLineEdit(QLineEdit):
    def __init__(self, parent=None):
        super(LazyLineEdit, self).__init__(parent)

    def setText(self, s):
        if self.text() == s:
            return
        else:
            QLineEdit.setText(self, s)
