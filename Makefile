TARGETS += nltrace
TARGETS += preload.so

all: $(TARGETS)

CFLAGS += -D_GNU_SOURCE -Wall -Wextra -I/usr/include/libnl3 -g -fPIC
LFLAGS += -lnl-3
LFLAGS += -lnl-route-3
LFLAGS += -lnl-genl-3
LFLAGS += -lnl-nf-3

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

COMMON_SRC += process.o
COMMON_SRC += nl_stub.o
COMMON_SRC += handlers.o
COMMON_SRC += descriptor.o

NLTRACE_SRC = $(COMMON_SRC)
NLTRACE_SRC += main.o
NLTRACE_SRC += syscalls.o
NLTRACE_SRC += tracer.o

PRELOAD_LFLAGS = $(LFLAGS)
PRELOAD_LFLAGS += -ldl -shared
PRELOAD_SRC = $(COMMON_SRC)
PRELOAD_SRC += ldpreload.o


nltrace: $(NLTRACE_SRC)
	$(CC) $(NLTRACE_SRC) $(LFLAGS) -o $@

preload.so: $(PRELOAD_SRC)
	$(CC) $(PRELOAD_SRC) $(PRELOAD_LFLAGS) -o $@

indent:
	indent *.c *.h

clean:
	rm -f *.[oais] *~ $(TARGETS)
