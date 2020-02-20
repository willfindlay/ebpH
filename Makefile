DIR=$(shell pwd)
SCRIPTSDIR=$(DIR)/scripts

LIBEBPHDIR=$(DIR)/src/libebph
LIBEBPHSRC=$(LIBEBPHDIR)/libebph.c
LIBEBPHOBJ=$(LIBEBPHSRC:.c=.so)

.PHONY: all, install, clean, systemd

all: $(LIBEBPHOBJ)

$(LIBEBPHOBJ): $(LIBEBPHSRC)
	cc -fPIC -shared -o $(LIBEBPHOBJ) $(LIBEBPHSRC)

install: $(LIBEBPHOBJ)
	cd $(SCRIPTSDIR) && sudo ./install.sh

systemd:
	sudo cp systemd/ebphd.service /etc/systemd/system/ebphd.service
	sudo systemctl enable ebphd.service

clean:
	rm $(LIBEBPHOBJ)
