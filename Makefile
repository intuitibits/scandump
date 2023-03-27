# Copyright (c) 2023 Intuitibits LLC
# Author: Adrian Granados <adrian@intuitibits.com>

CC = gcc
CFLAGS = -Wall -Werror -std=c99 -D_GNU_SOURCE -I/usr/include/libnl3/
LDFLAGS = -lnl-3 -lnl-genl-3 -lpcap

TARGET = scandump

SRCS = scandump.c

OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
