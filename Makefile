all : arp

arp : main.c
	gcc -o arp main.c arp.c arp.h
