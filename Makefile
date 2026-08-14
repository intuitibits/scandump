CC ?= gcc
CFLAGS ?=
CPPFLAGS ?=
LDFLAGS ?=

# Append to (rather than replace) any flags supplied by the environment, so
# distro build systems -- e.g. dh_auto_build exporting dpkg-buildflags'
# hardening options -- are honored.
override CFLAGS += -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -Wundef \
                   -Wstrict-prototypes -std=c99 -O2 -fstack-protector-strong \
                   -Werror
# -isystem so libnl3's own headers don't trip our warnings.
override CPPFLAGS += -isystem /usr/include/libnl3

# Fortify only if the environment hasn't already asked for a specific level:
# dpkg-buildflags passes -D_FORTIFY_SOURCE=3, and redefining it with a
# different value is a warning, which -Werror turns into a build failure.
ifeq (,$(findstring _FORTIFY_SOURCE,$(CFLAGS) $(CPPFLAGS)))
override CPPFLAGS += -D_FORTIFY_SOURCE=2
endif
override LDFLAGS += -lnl-3 -lnl-genl-3 -lpcap

TARGET = scandump

SRCS = scandump.c

OBJS = $(SRCS:.c=.o)

ASAN_FLAGS = -fsanitize=address,undefined -g -O1 -fno-omit-frame-pointer

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

asan: clean
	$(CC) $(CFLAGS) $(ASAN_FLAGS) $(CPPFLAGS) $(SRCS) -o $(TARGET)_asan $(LDFLAGS)

install: $(TARGET)
	mkdir -p $(DESTDIR)/usr/bin
	install -m 755 $(TARGET) $(DESTDIR)/usr/bin

clean:
	rm -f $(OBJS) $(TARGET) $(TARGET)_asan

.PHONY: all install clean asan
