DIR=$(shell pwd)
SCRIPTSDIR=$(DIR)/scripts

LIBEBPHDIR=$(DIR)/libebph
LIBEBPHSRC=$(LIBEBPHDIR)/libebph.c
LIBEBPHOBJ=$(LIBEBPHSRC:.c=.so)


.PHONY: all
all: $(LIBEBPHOBJ)

$(LIBEBPHOBJ): $(LIBEBPHSRC)
	cc -fPIC -shared -o $(LIBEBPHOBJ) $(LIBEBPHSRC)

.PHONY: install
install: $(LIBEBPHOBJ)
	cd $(SCRIPTSDIR) && sudo ./install.sh

.PHONY: unit
unit:
	sudo cp systemd/ebphd.service /etc/systemd/system/ebphd.service
	sudo systemctl enable ebphd.service

.PHONY: clean
clean:
	rm $(LIBEBPHOBJ)

.PHONY: dev
# Rule that make the package editable for development
dev:
	pip3 install -e . -r requirements.txt
