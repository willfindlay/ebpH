.PHONY: all
all:
	@echo "Run 'make install' to install."
	@echo "Run 'make systemd' to install and enable the systemd service."

.PHONY: dev
dev:
	sudo su -c "pip3 install -e . -r requirements.txt"

.PHONY: install
install:
	sudo su -c "pip3 install . --compile -r requirements.txt"

.PHONY: systemd
systemd:
	sudo su -c "/bin/sh systemd/create_service.sh"

test: dev
	$(MAKE) -C tests
