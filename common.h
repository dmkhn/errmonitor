/*
 *   common.h - Common definitions for errmonitor infrastructure
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

#ifndef __COMMON_H__
#define __COMMON_H__

#define MONITOR_MAX_STR_SZ       128
#define ZMQ_POLL_TIMEOUT_MAX     (5000) // 5secs
#define ZMQ_POLL_CTL_TIMEOUT_MAX (1000) // 1sec
#define ZMQ_LINGER_TIMEOUT_MAX   (1000) // 1sec

#endif /* __COMMON_H__ */
