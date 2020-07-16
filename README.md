# ebpH

## Description

ebpH is a modern host-based intrusion detection system for Linux 5.8+ that
leverages the power of Extended BPF (eBPF) to monitor processes and detect anomalous behavior.
This effectively constitutes an eBPF implementation of [pH (Process Homeostasis)](https://people.scs.carleton.ca/~mvvelzen/pH/pH.html).

## Disclaimer

This product comes with no warranty, and is built as a research system. It should be perfectly safe to run on your system due to the safety guarantees of eBPF, but we make no claims about functionality.

## Papers

### ebpH

- [My thesis](https://williamfindlay.com/written/thesis.pdf)

### pH

- [My supervisor's original dissertation on pH](https://people.scs.carleton.ca/~soma/pubs/soma-diss.pdf)
- [A Sense of Self for UNIX Processes](https://www.cs.unm.edu/~immsec/publications/ieee-sp-96-unix.pdf)
- [Lightweight Intrustion Detection for Networked Operating Systems](http://people.scs.carleton.ca/~soma/pubs/jcs1998.pdf)
- [Lookahead Pairs and Full Sequences: A Tale of Two Anomaly Detection Methods](http://people.scs.carleton.ca/~soma/pubs/inoue-albany2007.pdf)

## Prerequisites

1. Linux 5.8+ compiled with at least `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_TRACEPOINTS=y`
1. The **latest version** of bcc and bcc-python from https://github.com/iovisor/bcc
    - be sure to include `-DPYTHON_CMD=python3` in your build flags
1. Python 3.6+

## Installation

1. Install the prerequisites (see above).
1. `git clone https://github.com/willfindlay/ebpH`
1. `cd ebpH && sudo make install`

## How to Use / Examples

1. Run `$ sudo ebphd start` to start the daemon.
1. Run `$ ebph ps` to check monitored processes.
1. Run `$ ebph ps -p` to list all active profiles.
