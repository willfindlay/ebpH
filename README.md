# ebpH v0.1.1-AA (Aggressively Alpha)

## Description

This is an extremely early version of ebpH that serves as a proof of concept.
It "monitors" all executables on the system but can only really detect anomalies in **one at a time**
(this will be fixed in future versions).

See the instructions below for information on how to choose which profile is monitored.

## Prerequisites

1. The **latest version** of bcc and bcc-python from https://github.com/iovisor/bcc (I used the AUR to install mine; follow the instructions in their README)
    - The latest version is important because previous versions had a horrible bug that effectively broke python3 support
1. Python3.7
1. Pyside2 (5.12.0) `sudo pip3 install pyside2` (last time I checked the usual `--user` method does **not** work)

## Installation

1. Install the prerequisites (see above).
1. Clone this branch from the repo: `git clone --branch development https://github.com/HousedHorse/ebpH`
1. Run the Makefile to compile the `ui` files and `profile_loader`: `sudo make` (running this as root is important to set the correct permissions on `profile_loader`)

## Running

Change directory into `ebpH` and run `sudo ./gui.py`.

## Selecting a Binary to Monitor (Recommended Method)

Rather than deriving the key for yourself, you can run ebpH once,
run the binary you want, and find its key from the list of profiles.

If you would rather do things manually, the key for a binary is a 64 bit number with its inode in the lower 32
bits and the device number of its filesystem in the upper 32 bits.

Once you have the key you want, edit `bpf.c` and change the line that says `#define THE_KEY` to be the key you want.
