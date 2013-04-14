all: main

CFLAGS += -D_GNU_SOURCE -Wall -Wextra -O2 --save-temps

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

SRC = main.o handlers.o syscalls.o nl_stub.o

main: $(SRC)
	$(CC) $(SRC) $(LFLAGS) -o $@

indent:
	indent *.c *.h

clean:
	rm -f *.[oais] main *~

