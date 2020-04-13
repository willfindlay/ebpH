DIR=$(shell pwd)
SCRIPTSDIR=$(DIR)/scripts

LIBEBPHDIR=$(DIR)/ebpH/libebph
LIBEBPHSRC=$(LIBEBPHDIR)/libebph.c
LIBEBPHOBJ=$(LIBEBPHSRC:.c=.so)

.PHONY=
.PHONY+= all
.PHONY+= install
.PHONY+= clean
.PHONY+= package
.PHONY+= unit

all: $(LIBEBPHOBJ) package

$(LIBEBPHOBJ): $(LIBEBPHSRC)
	cc -fPIC -shared -o $(LIBEBPHOBJ) $(LIBEBPHSRC)

package:
	pip3 install -e . -r requirements.txt

install: $(LIBEBPHOBJ)
	cd $(SCRIPTSDIR) && sudo ./install.sh

unit:
	sudo cp systemd/ebphd.service /etc/systemd/system/ebphd.service
	sudo systemctl enable ebphd.service

clean:
	rm $(LIBEBPHOBJ)
