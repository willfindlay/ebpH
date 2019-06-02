#! /usr/bin/env python3

from PySide2.QtCore import QWaitCondition, QMutex

def init():
    global can_exit
    global profiles_saved
    global mutex
    profiles_saved = QWaitCondition()
    mutex          = QMutex()
