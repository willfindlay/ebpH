# pH

# eBPF

- extended Berkeley Packet Filter
- seamless kernel introspection
- virtual machine with hooks all over kernel

## Differences from BPF

- hooks for everything, not just networking packets
- more performant (modernized instruction set)
- backwards jumps in addition to forward jumps
  - allows looping

# Why Implement pH in eBPF?
