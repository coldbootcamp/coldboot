CFLAGS = -c -maes -msse4 -g -Wall

all: aes_app

aes: aes.c aes_locl.h
	gcc $(CFLAGS) aes.c

aes_cbc: aes_cbc.c aes_core.h
	gcc $(CFLAGS) aes_cbc.c

aes_trasform: aes_transform.S
	gcc $(CFLAGS) aes_transform.S

cbc: cbc.s
	gcc $(CFLAGS) cbc.s

aes_app: aes aes_cbc aes_trasform cbc
	gcc -o aes_app *.o

clean:
	rm -f aes_app *.o
