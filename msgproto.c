
#include <string.h>
#include "log.h"
#include "msgproto.h"

#define UNPACK_U32(msg,x) \
	x = (int)msg[0] << 24 | (int)msg[1] << 16 | (int)msg[2] << 8 | msg[3]; \
	msg += sizeof(int)

#define PACK_U32(x,msg) \
	*msg++ = (char)((x) >> 24); \
	*msg++ = (char)((x) >> 16); \
	*msg++ = (char)((x) >> 8); \
	*msg++ = (char)((x) & 0xFF)

void marshall_monitor_ctl_pkt(struct monitor_ctl_pkt_s *pkt, char *msg)
{
	PACK_U32(pkt->command, msg);
	memcpy(msg, pkt->detector, sizeof(pkt->detector));
}

void unmarshall_monitor_ctl_pkt(char *msg, struct monitor_ctl_pkt_s *pkt)
{
	UNPACK_U32(msg, pkt->command);
	memcpy(pkt->detector, msg, sizeof(pkt->detector));
}

void marshall_monitor_pkt(struct monitor_pkt_s *pkt, char *msg)
{
	PACK_U32(pkt->errcode, msg);
	memcpy(msg, pkt->detector, sizeof(pkt->detector));
}

void unmarshall_monitor_pkt(char *msg, struct monitor_pkt_s *pkt)
{
	UNPACK_U32(msg, pkt->errcode);
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
