#! /usr/bin/env python3

import os
from PySide2.QtGui import *
from PySide2.QtWidgets import *
from PySide2.QtCore import *

class ProfileSaveThread(QThread):
    # --- Signals ---
    update_progress = Signal(float)

    def __init__(self, bpf, parent=None):
        QThread.__init__(self, parent)
        self.bpf = bpf
        self.progress = 0

    def save_profiles(self):
        profile_hash = self.bpf["profile"]
        test_hash    = self.bpf["test_data"]
        train_hash   = self.bpf["train_data"]

        profile_dict = dict([(k.value, v) for k, v in profile_hash.items()])
        test_dict = dict([(k.value, v) for k, v in test_hash.items()])
        train_dict = dict([(k.value, v) for k, v in train_hash.items()])

        total = len(profile_dict)
        num_done = 0

        for k in profile_dict:
            profile  = profile_dict[k]
            test     = test_dict[k]
            train    = train_dict[k]
            filename = str(profile.key)

            profile_path = os.path.join(PROFILE_DIR, filename)

            # create path if it doesn't exist
            if not os.path.exists(os.path.dirname(profile_path)):
                try:
                    os.makedirs(os.path.dirname(profile_path))
                except OSError as exc: # Guard against race condition
                    if exc.errno != errno.EEXIST:
                        raise
            with open(profile_path, "w") as f:
                printb(b"".join([profile,test,train]),file=f,nl=0)

            num_done = num_done + 1
            self.progress = (num_done / float(total)) * 100
            self.update_progress.emit(self.progress)

    # save all profiles to disk
    def run(self):
        self.save_profiles()
