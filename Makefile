CC = gcc
CFLAGS = -Wall -Werror -std=c99 -I/usr/include/libnl3/
LDFLAGS = -lnl-3 -lnl-genl-3 -lpcap

TARGET = scandump

SRCS = scandump.c

OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

install: $(TARGET)
	mkdir -p $(DESTDIR)/usr/bin
	install -m 755 $(TARGET) $(DESTDIR)/usr/bin

clean:
	rm -f $(OBJS) $(TARGET)
