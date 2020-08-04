CC     = gcc
LDLAGS =
CFLAGS = -O0

EXES   = hello malicious

.PHONY: all
all: $(EXES)

.PHONY: clean
clean:
	rm -f $(EXES) *.o

hello: hello.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o hello hello.c

malicious: malicious.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o malicious malicious.c
