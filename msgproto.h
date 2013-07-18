
#ifndef __MSGPROTO_H__
#define __MSGPROTO_H__

#include <stdint.h>

#define DEFAULT_PORT        56789
#define DEFAULT_ADDRESS     "localhost"
#define DETECTOR_SIZE       32

struct monitor_pkt_s {
	int pid;
	int errcode;
	long tv_sec;
	long tv_usec;
	char detector[DETECTOR_SIZE];
};

void marshall_monitor_pkt(struct monitor_pkt_s *pkt, char *msg);
void unmarshall_monitor_pkt(char *msg, struct monitor_pkt_s *pkt);

#endif /* __MSGPROTO_H__ */
