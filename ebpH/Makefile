QML = $(shell ls *.ui)
RES = $(shell ls *.qrc)
QMLPY = $(QML:.ui=.py)
RESPY = $(RES:.qrc=_rc.py)

.PHONY: all, install, clean

all: $(QMLPY) $(RESPY) ebpH_command

$(QMLPY): $(QML)
	$(foreach i, $(QML), pyside2-uic $(i) > $(i:.ui=.py);)

$(RESPY):
	$(foreach i, $(RES), pyside2-rcc $(i) > $(i:.qrc=_rc.py);)

ebpH_command: ebpH_command.c
	gcc -o ebpH_command ebpH_command.c

# TODO: change this to install the script for real
install:
	chown root:root ebpH_command && chmod 700 ebpH_command

clean:
	@rm $(QMLPY) $(RESPY) ebpH_command
