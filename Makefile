all: nltrace

CFLAGS += -D_GNU_SOURCE -Wall -Wextra -I/usr/include/libnl3 -g
LFLAGS += -lnl-3
LFLAGS += -lnl-route-3
LFLAGS += -lnl-genl-3
LFLAGS += -lnl-nf-3

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

SRC = descriptor.o
SRC += handlers.o
SRC += main.o
SRC += process.o
SRC += syscalls.o
SRC += tracer.o
SRC += nl_stub.o

nltrace: $(SRC)
	$(CC) $(SRC) $(LFLAGS) -o $@

indent:
	indent *.c *.h

clean:
	rm -f *.[oais] nltrace *~
