#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>

#define USE_STDERR
#define USE_EXTRA_DEBUG

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
#define verbose(...) do_log(3, __VA_ARGS__)

#endif /* __LOG_H__ */
