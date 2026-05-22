PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
CC      ?= cc
CFLAGS  ?= -O2 -pipe
LDFLAGS ?=
LDLIBS  ?= -lldns

SRCDIR  = src
TOMLDIR = third_party/tomlc99
OUTDIR  = out
TARGET  = $(OUTDIR)/weirdns

CFLAGS  += -Wall -Wextra -Wpedantic -I$(TOMLDIR)
LDFLAGS += -static-libgcc

OBJS    = $(SRCDIR)/main.o $(SRCDIR)/toml.o

$(TARGET): $(OBJS) | $(OUTDIR)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(OUTDIR):
	mkdir -p $@

$(SRCDIR)/main.o: $(SRCDIR)/main.c $(TOMLDIR)/toml.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(SRCDIR)/toml.o: $(TOMLDIR)/toml.c $(TOMLDIR)/toml.h
	$(CC) $(CFLAGS) -c -o $@ $<

all: $(TARGET)

debug: CFLAGS += -g -O0 -DDEBUG
debug: clean all

release: CFLAGS += -g -O2 -fprofile-arcs -ftest-coverage
release: LDFLAGS += -fprofile-arcs -ftest-coverage
release: clean all

clean:
	rm -rf $(OUTDIR)
	rm -f $(OBJS)

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

.PHONY: all debug profile clean install uninstall
