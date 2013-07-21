
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

void marshall_monitor_ctl_rsp_pkt(struct monitor_ctl_rsp_pkt_s *pkt, char *msg)
{
	*msg++ = (char)(pkt->response >> 24);
	*msg++ = (char)(pkt->response >> 16);
	*msg++ = (char)(pkt->response >> 8);
	*msg++ = (char)(pkt->response & 0xFF);

	*msg++ = (char)(pkt->command >> 24);
	*msg++ = (char)(pkt->command >> 16);
	*msg++ = (char)(pkt->command >> 8);
	*msg++ = (char)(pkt->command & 0xFF);

	memcpy(msg, pkt->detector, sizeof(pkt->detector));
}

void unmarshall_monitor_ctl_rsp_pkt(char *msg, struct monitor_ctl_rsp_pkt_s *pkt)
{
	pkt->response = (int)msg[0] << 24 |
			(int)msg[1] << 16 |
			(int)msg[2] << 8 |
			msg[3];
	msg += sizeof(int);

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

void marshall_monitor_rsp_pkt(struct monitor_rsp_pkt_s *pkt, char *msg)
{
	*msg++ = (char)(pkt->response >> 24);
	*msg++ = (char)(pkt->response >> 16);
	*msg++ = (char)(pkt->response >> 8);
	*msg++ = (char)(pkt->response & 0xFF);

	*msg++ = (char)(pkt->errcode >> 24);
	*msg++ = (char)(pkt->errcode >> 16);
	*msg++ = (char)(pkt->errcode >> 8);
	*msg++ = (char)(pkt->errcode & 0xFF);

	memcpy(msg, pkt->detector, sizeof(pkt->detector));
}

void unmarshall_monitor_rsp_pkt(char *msg, struct monitor_rsp_pkt_s *pkt)
{
	pkt->response = (int)msg[0] << 24 |
			(int)msg[1] << 16 |
			(int)msg[2] << 8 |
			msg[3];
	msg += sizeof(int);

	pkt->errcode = (int)msg[0] << 24 |
			(int)msg[1] << 16 |
			(int)msg[2] << 8 |
			msg[3];
	msg += sizeof(int);

	memcpy(pkt->detector, msg, sizeof(pkt->detector));
}


void dump_raw_pkt(const char *msg, int len)
{
#ifdef USE_EXTRA_DEBUG
	int i;
	char str[512];
	char *ptr = str;

	for (i = 0; i < len; i++) {
		sprintf(ptr, "%02X ", msg[i] & 0xFF);
		ptr += 3;
	}
	debug("packet: [%s]", str);
#endif
}

