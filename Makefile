# Copyright 2019 Darius Neatu <neatudarius@gmail.com>

# compiler setup
CC=gcc
CFLAGS=-Wall -Wextra -std=c99

# define targets
TARGET=main

build: $(TARGET).c
	$(CC) $(CFLAGS) $(TARGET).c -o archiver

pack:
	zip -FSr 312CA_SaraevStefan_Tema3.zip README Makefile *.c *.h

clean:
	rm -f $(TARGET)
