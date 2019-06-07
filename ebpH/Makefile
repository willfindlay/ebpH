QML = $(shell ls *.ui)
RES = $(shell ls *.qrc)
QMLPY = $(QML:.ui=.py)
RESPY = $(RES:.qrc=_rc.py)
PY = $(QMLPY) $(RESPY)

all: $(PY) ebpH_command

$(QMLPY): $(QML)
	$(foreach i, $(QML), pyside2-uic $(i) > $(i:.ui=.py);)

$(RESPY): $(RES)
	$(foreach i, $(RES), pyside2-rcc $(i) > $(i:.qrc=_rc.py);)

ebpH_command: ebpH_command.c
	gcc -o profile_loader profile_loader.c && chown root:root profile_loader && chmod 700 profile_loader

clean:
	@rm $(PY)
