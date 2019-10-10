# ebpH v1.1.1 Beta

## Description

A daemon (can also be started as a foreground process with the `--nodaemon` flag) that monitors every process on the system
and watches for anomalous system calls.

See the instructions below for information on how to choose which profile is monitored.

## Selecting a Binary to Monitor (Recommended Method)

Rather than deriving the key for yourself, you can run ebpH once,
run the binary you want, and find its key from the list of profiles.

If you would rather do things manually, the key for a binary is a 64 bit number with its inode in the lower 32
bits and the device number of its filesystem in the upper 32 bits.

Once you have the key you want, edit `bpf.c` and change the line that says `#define THE_KEY` to be the key you want.

## Viewing the Logs

The ebpH logfile is kept in `/var/log/ebph.log` by default. This can be configured in config.py, but doing so may break docker support.

## Docker

**Make sure you have `docker` and `docker-compose` installed.** This should be all you need.

Run the following commands:

```
$ docker-compose up --build
```

Subsequently, the app can be run with:

```
$ docker-compose up
```

## Prerequisites

1. Linux 5.3 or higher (for now)
1. The **latest version** of bcc and bcc-python from https://github.com/iovisor/bcc (I used the AUR to install mine; follow the instructions in their README)
    - The latest version is important because previous versions had a horrible bug that effectively broke python3 support
1. Python 3.7

## Installation

1. Install the prerequisites (see above).
1. Clone the development branch from the repo: `git clone --branch development https://github.com/HousedHorse/ebpH`
1. Run `$ make && make install`. The scripts will ask for sudo as needed.

## Running

Run `$ sudo ./ebphd start` in the root directory of this project to start the daemon.
