# Thesis
More stuff might go here later.

Code is in the ebpH directory.

## Questions for Anil

- profiles for process already running when ebpH launches?
    - the issue is: how do we snag a filename without peeking at execve args...
    - actually a workaround could be changing startup order for ebpH (?)
    - https://serverfault.com/questions/176055/how-to-change-linux-services-startup-boot-order
- lookahead pairs... how far back do we go??
    - the bitmap method will NOT work in eBPF -- the stack limitations are far too punishing
