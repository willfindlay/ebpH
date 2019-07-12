DIR=$(shell pwd)
SCRIPTSDIR=$(DIR)/scripts
CDIR=$(shell dirname $(shell readlink -f $(shell find $(DIR) -name ebpH_command.c)))

.PHONY: all, gui, install, clean

all: gui ebpH_command

gui:
	cd $(SCRIPTSDIR) && ./build-gui.sh

ebpH_command: $(CDIR)/ebpH_command.c
	gcc -o ebpH_command $(CDIR)/ebpH_command.c

# TODO: change this to install the script for real
install:
	chown root:root ebpH_command && chmod 700 ebpH_command

clean:
	@rm ebpH_command
