/*
 *   monitorpkt.c - Error monitor protocol
 *   Copyright (C) 2013 Denis Mukhin <dennis.mukhin@gmail.com>
 *
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <string.h>
#include "log.h"
#include "monitorpkt.h"

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
