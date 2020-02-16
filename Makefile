DIR=$(shell pwd)
SCRIPTSDIR=$(DIR)/scripts
PYTHONPATH=$(DIR)/src/python

.PHONY: all, install

all:
	$(error "Please run sudo make install")

install:
	cd $(SCRIPTSDIR) && ./install.sh
