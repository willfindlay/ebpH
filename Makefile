DIR=$(shell pwd)
SCRIPTSDIR=$(DIR)/scripts
PYTHONPATH=$(DIR)/src/python

.PHONY: all, install, test

ifeq (, $(shell which pipenv))
	pip3 install pipenv
endif

all:
	$(error "Please run sudo make install")

test:
	PYTHONPATH=$(PYTHONPATH) python3 -m unittest discover

install:
	cd $(SCRIPTSDIR) && ./install.sh
