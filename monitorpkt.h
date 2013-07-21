/*
 *   monitorpkt.h - Error monitor protocol
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

#ifndef __MONITORPKT_H__
#define __MONITORPKT_H__

#include <stdint.h>

#define DEFAULT_PORT        56789
#define DEFAULT_CTL_PORT    56790
#define DEFAULT_ADDRESS     "localhost"
#define DETECTOR_SIZE       32

enum monitor_rsp_code {
	MONITOR_RSP_OK,
	MONITOR_RSP_FAILURE,
};

struct monitor_pkt_s {
	int errcode;
	char detector[DETECTOR_SIZE];
};

enum monitor_cmd {
	MONITOR_CMD_DUMMY = 0,
	MONITOR_CMD_KILL,
	MONITOR_CMD_GRACEFULL_KILL,
};

struct monitor_ctl_pkt_s {
	int command;
	char detector[DETECTOR_SIZE];
};

void marshall_monitor_ctl_pkt(struct monitor_ctl_pkt_s *pkt, char *msg);
void unmarshall_monitor_ctl_pkt(char *msg, struct monitor_ctl_pkt_s *pkt);

void marshall_monitor_pkt(struct monitor_pkt_s *pkt, char *msg);
void unmarshall_monitor_pkt(char *msg, struct monitor_pkt_s *pkt);

void dump_raw_pkt(const char *msg, int len);

#endif /* __MONITORPKT_H__ */
