CC ?= gcc
CFLAGS ?= -O2
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?=
PKG_CONFIG ?= pkg-config
INSTALL ?= install

PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man

# Warnings are errors by default so new ones get fixed rather than ignored.
# Distribution builds pass WERROR= so a newer compiler's new warnings don't
# turn into build failures.
WERROR ?= -Werror

# Append to (rather than replace) any flags supplied by the environment, so
# distro build systems -- e.g. dh_auto_build exporting dpkg-buildflags'
# hardening options -- are honored.
override CFLAGS += -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -Wundef \
                   -Wstrict-prototypes -std=c99 -fstack-protector-strong \
                   $(WERROR)

# Library flags come from pkg-config, falling back to the usual Debian/Fedora
# locations when it (or a .pc file) is unavailable.
NL_CFLAGS := $(shell $(PKG_CONFIG) --cflags libnl-genl-3.0 2>/dev/null || echo -I/usr/include/libnl3)
NL_LIBS := $(shell $(PKG_CONFIG) --libs libnl-genl-3.0 2>/dev/null || echo -lnl-genl-3 -lnl-3)
PCAP_CFLAGS := $(shell $(PKG_CONFIG) --cflags libpcap 2>/dev/null)
PCAP_LIBS := $(shell $(PKG_CONFIG) --libs libpcap 2>/dev/null || echo -lpcap)

# -isystem so libnl3's own headers don't trip our warnings.
override CPPFLAGS += $(patsubst -I%,-isystem %,$(NL_CFLAGS) $(PCAP_CFLAGS))

# Fortify only if the environment hasn't already asked for a specific level:
# dpkg-buildflags passes -D_FORTIFY_SOURCE=3, and redefining it with a
# different value is a warning, which -Werror turns into a build failure.
ifeq (,$(findstring _FORTIFY_SOURCE,$(CFLAGS) $(CPPFLAGS)))
override CPPFLAGS += -D_FORTIFY_SOURCE=2
endif
override LDLIBS += $(NL_LIBS) $(PCAP_LIBS)

TARGET = scandump

MANPAGE = scandump.8

SRCS = scandump.c

OBJS = $(SRCS:.c=.o)

# Tests that need no wireless hardware; see tests/test_scandump.c.
TEST = tests/test_scandump

VERSION := $(shell sed -n 's/^.define VERSION "\(.*\)"/\1/p' scandump.c)

ASAN_FLAGS = -fsanitize=address,undefined -g -O1 -fno-omit-frame-pointer

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $(TARGET) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(TEST): tests/test_scandump.c $(SRCS)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $< -o $@ $(LDLIBS)

check: $(TARGET) $(TEST)
	./$(TEST)
	sh tests/cli.sh ./$(TARGET)

asan: clean
	$(CC) $(CFLAGS) $(ASAN_FLAGS) $(CPPFLAGS) $(LDFLAGS) $(SRCS) -o $(TARGET)_asan $(LDLIBS)

install: $(TARGET)
	$(INSTALL) -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	$(INSTALL) -m 0644 $(MANPAGE) $(DESTDIR)$(MANDIR)/man8/$(MANPAGE)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET) $(DESTDIR)$(MANDIR)/man8/$(MANPAGE)

# Release tarball of the committed tree (HEAD), laid out like GitHub's tag
# archives: scandump-$(VERSION)/...
dist:
	git archive --format=tar.gz --prefix=$(TARGET)-$(VERSION)/ \
	  -o $(TARGET)-$(VERSION).tar.gz HEAD

clean:
	rm -f $(OBJS) $(TARGET) $(TARGET)_asan $(TARGET)-*.tar.gz $(TEST)

.PHONY: all check install uninstall dist clean asan
