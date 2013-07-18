
all:
	gcc errgen.c msgproto.c -g -o errgen -lzmq
	gcc monitor.c msgproto.c -g -o monitor -lzmq -lpthread

clean:
	rm errgen monitor

