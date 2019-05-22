QML = $(shell ls *.ui)
RES = $(shell ls *.qrc)
QMLPY = $(QML:.ui=.py)
RESPY = $(RES:.qrc=_rc.py)
PY = $(QMLPY) $(RESPY)

all: $(PY)

$(QMLPY): $(QML)
	$(foreach i, $(QML), pyside2-uic $(i) > $(i:.ui=.py))

$(RESPY): $(RES)
	$(foreach i, $(RES), pyside2-rcc $(i) > $(i:.qrc=_rc.py))

clean:
	@rm $(PY)
