# Thesis
More stuff might go here later.

Code is in the ebpH directory.

## New Discoveries

- can lookup structs from a map and then write to them
    - no stack space necessary?!?
    - https://git.kernel.org/pub/scm/linux/kernel/git/davem/net-next.git/commit/?id=5722569bb9c3bd922c4f10b5b2912fe88c255312

## Questions for Anil

- profiles for process already running when ebpH launches?
    - https://serverfault.com/questions/176055/how-to-change-linux-services-startup-boot-order
- lookahead pairs... how far back do we go??
    - the bitmap method will NOT work in eBPF -- the stack limitations are far too punishing
    - maybe arrays of arrays or maps of maps in BPF?
    - is this possible? ...maybe
