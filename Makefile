DIR=$(shell pwd)
SCRIPTSDIR=$(DIR)/scripts

.PHONY: all, install

all: # temporary
	@echo "Please run: sudo make install"

install:
	cd $(SCRIPTSDIR) && ./install.sh
