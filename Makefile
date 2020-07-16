dev:
	pip3 install -e . -r requirements.txt

install:
	pip3 install . -r requirements.txt

test: dev
	$(MAKE) -C tests
