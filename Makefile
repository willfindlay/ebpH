DIR=$(shell pwd)
SCRIPTSDIR=$(DIR)/scripts

LIBEBPHDIR=$(DIR)/src/libebph
LIBEBPHSRC=$(LIBEBPHDIR)/libebph.c
LIBEBPHOBJ=$(LIBEBPHSRC:.c=.so)

.PHONY: all, install, clean

all: $(LIBEBPHOBJ)

$(LIBEBPHOBJ): $(LIBEBPHSRC)
	cc -fPIC -shared -o $(LIBEBPHOBJ) $(LIBEBPHSRC)

install: $(LIBEBPHOBJ)
	cd $(SCRIPTSDIR) && sudo ./install.sh

clean:
	rm $(LIBEBPHOBJ)
