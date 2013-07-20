
#ifndef __MSGPROTO_H__
#define __MSGPROTO_H__

#include <stdint.h>

#define DEFAULT_PORT        56789
#define DEFAULT_CTL_PORT    56790
#define DEFAULT_ADDRESS     "localhost"
#define DETECTOR_SIZE       32

struct monitor_pkt_s {
	int errcode;
	long tv_sec;
	long tv_usec;
	char detector[DETECTOR_SIZE];
};

enum monitor_cmd {
	MONITOR_CMD_DUMMY = 0,
	MONITOR_CMD_GRACEFULL_KILL,
	MONITOR_CMD_KILL,
};

struct monitor_ctl_pkt_s {
	int command;
	char detector[DETECTOR_SIZE];
};

void marshall_monitor_ctl_pkt(struct monitor_ctl_pkt_s *pkt, char *msg);
void unmarshall_monitor_ctl_pkt(char *msg, struct monitor_ctl_pkt_s *pkt);

void marshall_monitor_pkt(struct monitor_pkt_s *pkt, char *msg);
void unmarshall_monitor_pkt(char *msg, struct monitor_pkt_s *pkt);

void dump_raw_pkt(const char *msg);

#endif /* __MSGPROTO_H__ */
