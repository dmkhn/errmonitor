
all:
	gcc errgen.c errgencfg.c monitorpkt.c -o errgen -lzmq
	gcc monitor.c monitorcfg.c monitorpkt.c -o monitor -lzmq

clean:
	rm -f errgen monitor *.o

