all: main

CFLAGS += -D_GNU_SOURCE -Wall -Wextra -I/usr/include/libnl3 -g
LFLAGS += -lnl-3

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

SRC = main.o handlers.o syscalls.o nl_stub.o

main: $(SRC)
	$(CC) $(SRC) $(LFLAGS) -o $@

indent:
	indent *.c *.h

clean:
	rm -f *.[oais] main *~

