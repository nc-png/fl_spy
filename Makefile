CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
CFLAGS  += $(shell pkg-config --cflags ncursesw 2>/dev/null)
LIBS     = $(shell pkg-config --libs ncursesw 2>/dev/null || echo -lncursesw)

fl_spy: fl_spy.c online.h
	$(CC) $(CFLAGS) -o $@ fl_spy.c $(LIBS)

install: fl_spy
	install -m 755 fl_spy /usr/local/bin/fl_spy

clean:
	rm -f fl_spy

.PHONY: install clean
