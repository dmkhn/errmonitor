
#include <string.h>
#include "log.h"
#include "msgproto.h"

void marshall_monitor_ctl_pkt(struct monitor_ctl_pkt_s *pkt, char *msg)
{
	*msg++ = (char)(pkt->command >> 24);
	*msg++ = (char)(pkt->command >> 16);
	*msg++ = (char)(pkt->command >> 8);
	*msg++ = (char)(pkt->command & 0xFF);

	memcpy(msg, pkt->detector, sizeof(pkt->detector));
}

void unmarshall_monitor_ctl_pkt(char *msg, struct monitor_ctl_pkt_s *pkt)
{
	pkt->command = (int)msg[0] << 24 |
			(int)msg[1] << 16 |
			(int)msg[2] << 8 |
			msg[3];
	msg += sizeof(int);

	memcpy(pkt->detector, msg, sizeof(pkt->detector));
}

void marshall_monitor_pkt(struct monitor_pkt_s *pkt, char *msg)
{
	*msg++ = (char)(pkt->errcode >> 24);
	*msg++ = (char)(pkt->errcode >> 16);
	*msg++ = (char)(pkt->errcode >> 8);
	*msg++ = (char)(pkt->errcode & 0xFF);

	*msg++ = (char)(pkt->tv_sec >> 24);
	*msg++ = (char)(pkt->tv_sec >> 16);
	*msg++ = (char)(pkt->tv_sec >> 8);
	*msg++ = (char)(pkt->tv_sec & 0xFF);

	*msg++ = (char)(pkt->tv_usec >> 24);
	*msg++ = (char)(pkt->tv_usec >> 16);
	*msg++ = (char)(pkt->tv_usec >> 8);
	*msg++ = (char)(pkt->tv_usec & 0xFF);

	memcpy(msg, pkt->detector, sizeof(pkt->detector));
}

void unmarshall_monitor_pkt(char *msg, struct monitor_pkt_s *pkt)
{
	pkt->errcode = (int)msg[0] << 24 |
			(int)msg[1] << 16 |
			(int)msg[2] << 8 |
			msg[3];
	msg += sizeof(int);

	pkt->tv_sec = (int)msg[0] << 24 |
			(int)msg[1] << 16 |
			(int)msg[2] << 8 |
			msg[3];
	msg += sizeof(int);

	pkt->tv_usec = (int)msg[0] << 24 |
			(int)msg[1] << 16 |
			(int)msg[2] << 8 |
			msg[3];
	msg += sizeof(int);

	memcpy(pkt->detector, msg, sizeof(pkt->detector));
}

void dump_raw_pkt(const char *msg)
{
#ifdef USE_EXTRA_DEBUG
	int i;
	char str[3 * sizeof(struct monitor_pkt_s)];
	char *ptr = str;

	for (i = 0; i < sizeof(struct monitor_pkt_s); i++) {
		sprintf(ptr, "%02X ", msg[i] & 0xFF);
		ptr += 3;
	}
	debug("packet: [%s]", str);
#endif
}
