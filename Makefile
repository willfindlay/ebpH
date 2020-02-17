DIR=$(shell pwd)
SCRIPTSDIR=$(DIR)/scripts
LIBEBPHDIR=$(DIR)/src/libebph

.PHONY: all, install

all: $(LIBEBPHDIR)/libebph.so

$(LIBEBPHDIR)/libebph.so: $(LIBEBPHDIR)/libebph.c
	cd $(LIBEBPHDIR) && cc -fPIC -shared -o libebph.so libebph.c

install:
	cd $(SCRIPTSDIR) && ./install.sh
