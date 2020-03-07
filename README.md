# ebpH v0.6.0

## Description

ebpH is an eBPF daemon to monitor all processes on the system and watch for anomalous system calls. Effectively constitutes an eBPF implementation of [pH (Process Homeostasis)](https://people.scs.carleton.ca/~mvvelzen/pH/pH.html).

## Disclaimer

This product comes with no warranty, and is built as a research system. It should be perfectly safe to run on your system due to the safety guarantees of eBPF, but we make no claims about functionality. This project is very much a work in progress at this stage.

## Papers

### ebpH

- [My thesis proposal](https://williamfindlay.com/written/thesis-proposal.pdf)

### pH

- [My supervisor's original dissertation on pH](https://people.scs.carleton.ca/~soma/pubs/soma-diss.pdf)
- [A Sense of Self for UNIX Processes](https://www.cs.unm.edu/~immsec/publications/ieee-sp-96-unix.pdf)
- [Lightweight Intrustion Detection for Networked Operating Systems](http://people.scs.carleton.ca/~soma/pubs/jcs1998.pdf)
- [Lookahead Pairs and Full Sequences: A Tale of Two Anomaly Detection Methods](http://people.scs.carleton.ca/~soma/pubs/inoue-albany2007.pdf)

## Prerequisites

1. Linux 5.3+
1. The **latest version** of bcc and bcc-python from https://github.com/iovisor/bcc
    - be sure to include `-DPYTHON_CMD=python3` in your build flags!
1. Python 3.7+

## Installation

1. Install the prerequisites (see above).
1. Clone the development branch from the repo: `git clone https://github.com/willfindlay/ebpH`
1. Run `$ make install`. You will be prompted for your password.
1. For automatic startup with systemd, run `$ make systemd`. You will be prompted for your password.

## Running

1. Run `$ sudo ebph-admin start` to start the daemon.
1. Run `$ sudo ebph-admin status` to check system status.
1. Run `$ sudo ebph-ps` to check monitored processes.
1. Run `$ sudo ebph-ps -p` to list all active profiles.
1. Run `$ sudo ebph-admin <command>` to issue commands to the daemon.

## Trying it Out with Docker

**Make sure you have `docker` and `docker-compose` installed.** Your Linux kernel version should also meet the minimum requirements specified below (i.e. at least 5.3).

Run the following commands:

```
$ docker-compose build --no-cache
$ docker-compose up
```

Subsequently, the app can be run with:

```
$ docker-compose up
```
