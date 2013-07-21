/*
 *   log.h - Logging facility for errmonitor
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

#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>

/* Define to have all log messages in stderr */
#undef USE_STDERR
/* Define to use special debugging facility (packets) */
#undef USE_EXTRA_DEBUG

/* Used for filtering log messages */
extern int verbosity;

static inline void __attribute__((__format__(__printf__,2,3)))
do_log(int level, const char *fmt, ...)
{
	va_list ap;

	if (level <= verbosity) {
		va_start(ap, fmt);
#ifdef USE_STDERR
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
#else
		vsyslog(LOG_INFO, fmt, ap);
#endif
		va_end(ap);
	}
}

static inline void __attribute__((__format__(__printf__,1,2)))
error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
#ifdef USE_STDERR
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
#else
	vsyslog(LOG_INFO, fmt, ap);
#endif
	va_end(ap);
}

#define info(...) do_log(1, __VA_ARGS__)
#define debug(...) do_log(2, __VA_ARGS__)

#endif /* __LOG_H__ */
