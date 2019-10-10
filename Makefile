DIR=$(shell pwd)
SCRIPTSDIR=$(DIR)/scripts
PYTHONPATH=$(DIR)/src/python

.PHONY: all, install, test

ifeq (, $(shell which pipenv))
	pip3 install pipenv
endif

all:
	$(error "Please run sudo make install")

pipenv:
	pipenv run pip freeze | grep pytest || pipenv install pytest

test: pipenv
	PYTHONPATH=$(PYTHONPATH) pipenv run pytest

install:
	cd $(SCRIPTSDIR) && ./install.sh
