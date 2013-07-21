
all:
	gcc errgen.c errgencfg.c msgproto.c -o errgen -lzmq
	gcc monitor.c monitorcfg.c msgproto.c -o monitor -lzmq

clean:
	rm -f errgen monitor *.o

