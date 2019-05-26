#! /usr/bin/env python3
from PySide2.QtGui import *
from PySide2.QtWidgets import *
from PySide2.QtCore import *
from PySide2.QtCharts import *

class SquareChartContainer(QWidget):
    def resizeEvent(self, event):
        if event.size().width() > event.size().height():
            self.resize(event.size().height(),event.size().height())
        else:
            self.resize(event.size().width(),event.size().width())
        event.accept()

