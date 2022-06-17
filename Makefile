
# author: Filip Brna, xbrnaf00
# Projekt: IPK 2.projekt varianta ZETA (Sniffer)

CC=g++
CFLAGS=-std=c++17

all:
	$(CC) $(CFLAGS) ipk-sniffer.cpp -lpcap -o ipk-sniffer