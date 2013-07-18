#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <zmq.h>
#include <getopt.h>
#include <syslog.h>

#include "msgproto.h"

#define ERRGEN_DEFAULT_SYSLOGNAME  "errgen"
#define ERRGEN_DEFAULT_TIMEOUT     5000 // 5sec

/** Verbosity requested from command line */
static int verbosity = 1;

static int need_run = 1;

void __attribute__((__format__(__printf__,2,3)))
do_log(int level, const char *fmt, ...)
{
	va_list ap;

	if (level <= verbosity) {
		va_start(ap, fmt);
		vsyslog(LOG_INFO, fmt, ap);
		va_end(ap);
	}
}

void error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(LOG_ERR, fmt, ap);
	va_end(ap);
}

#define info(...) do_log(1, __VA_ARGS__)
#define debug(...) do_log(2, __VA_ARGS__)
#define verbose(...) do_log(3, __VA_ARGS__)

#define MAX_UUID_LEN    DETECTOR_SIZE
#define MAX_ADDRESS_LEN 64

struct errgen_cfg {
	int port;
	char address[MAX_ADDRESS_LEN];
	char uuid[MAX_UUID_LEN];
	int timeout;
};

struct errgen_ctx {
	struct errgen_cfg conf;
	void *zmq_ctx;
	void *zmq_sock;
	int cnt;
	pid_t pid;
};

static void print_version(const char *argv0) {
	printf(
		"%s v.1.0 Fake error generator\n"
		"Demonstrates the libzmq usage\n", argv0);
}

static void print_help(const char *argv0) {
	printf(
		"%s [options]\n"
		"    -h --help                Show this help\n"
		"    -v --version             Show version\n"
		"    -p --port=NUM            Set monitor port\n"
		"    -a --address=ADDR        Set monitor hostname\n"
		"    -u --uuid=STRING         Set UUID of the client\n"
		"    -t --timeout=NUM         Set timeout in secs to generate err report\n"
		"    -d --debug               Increase output verbosity\n"
		"\n", argv0);
}

static int parse_command_line(struct errgen_cfg *cfg,
		int argc, char *argv[]) {
	int opt, len;
	static const struct option long_options[] = {
		{ "version",	no_argument,		NULL, 'v' },
		{ "help",		no_argument,		NULL, 'h' },
		{ "debug",		no_argument,		NULL, 'd' },
		{ "uuid",		required_argument,	NULL, 'u' },
		{ "port",		optional_argument,	NULL, 'p' },
		{ "address",	optional_argument,	NULL, 'a' },
		{ "timeout",	optional_argument,	NULL, 't' },
		{ NULL, 0, NULL, 0 }
	};

	if (argc < 2) {
		print_help(argv[0]);
		exit(0);
	}

	while ((opt = getopt_long(argc, argv, "hvd:u:p:a:t",
			long_options, NULL)) >= 0) {
		switch(opt) {
		case 'h':
			print_help(argv[0]);
			exit(0);
			break;

		case 'v':
			print_version(argv[0]);
			exit(0);
			break;

		case 'd':
			verbosity++;
			break;

		case 'u':
			len = strlen(optarg);
			if (len > MAX_UUID_LEN) {
				len = MAX_UUID_LEN;
			}
			memcpy(cfg->uuid, optarg, len);
			break;

		case 'p':
			cfg->port = atoi(optarg);
			break;

		case 'a':
			len = strlen(optarg);
			if (len > MAX_ADDRESS_LEN) {
				len = MAX_ADDRESS_LEN;
			}
			memcpy(cfg->address, optarg, len);
			break;

		case 't':
			cfg->port = atoi(optarg);
			break;

		default:
			return -1;
		}
	}

	if (optind < argc) {
		fprintf(stderr, "ERROR: Too many arguments\n");
		return -1;
	}

	return 0;
}

static int errgen_cfg_init(struct errgen_cfg *cfg)
{
	cfg->port = DEFAULT_PORT;
	cfg->timeout = ERRGEN_DEFAULT_TIMEOUT;
	strcpy(cfg->address, DEFAULT_ADDRESS);

	return 0;
}

static void errgen_sig_handler(int sig)
{
	if (sig == SIGTERM || sig == SIGINT) {
		need_run = 0;
		info("cathed signal %d", sig);
	}
}

static int errgen_register_sighandlers(void)
{
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	if (sigemptyset(&act.sa_mask) < 0) {
		fprintf(stderr, "sigemptyset()\n");
		return 1;
	}
	if (sigaddset(&act.sa_mask, SIGINT) < 0) {
		fprintf(stderr, "sigaddset()\n");
		return 1;
	}
	if (sigaddset(&act.sa_mask, SIGTERM) < 0) {
		fprintf(stderr, "sigaddset()\n");
		return 1;
	}

	act.sa_handler = errgen_sig_handler;
	if (sigaction(SIGTERM, &act, NULL) < 0) {
		fprintf(stderr, "sigaction()\n");
		return 1;
	}
	if (sigaction(SIGINT, &act, NULL) < 0) {
		fprintf(stderr, "sigaction()\n");
		return 1;
	}

	return 0;
}

static int errgen_setup(struct errgen_ctx *ctx, int argc, char *argv[])
{
	if (errgen_cfg_init(&ctx->conf)) {
		fprintf(stderr, "ERROR: unrecoverable error\n");
		return -1;
	}

	if (parse_command_line(&ctx->conf, argc, argv)) {
		fprintf(stderr, "Type '--help' for more information\n");
		return -1;
	}

	if (errgen_register_sighandlers()) {
		fprintf(stderr, "ERROR: failed to register signal handlers\n");
		return -1;
	}

	openlog(ERRGEN_DEFAULT_SYSLOGNAME, LOG_PID|LOG_CONS, LOG_DAEMON);

	info("  monitor hostname: %s", ctx->conf.address);
	info("  port: %d", ctx->conf.port);
	info("  uuid: %s", ctx->conf.uuid);
	info("  timeout: %d", ctx->conf.timeout);

	ctx->pid = getpid();

	return 0;
}

static int connect_to_server(struct errgen_ctx *ctx)
{
	char uri[MAX_ADDRESS_LEN];

	info("Connecting to monitor at %s:%d...",
			ctx->conf.address, ctx->conf.port);
	ctx->zmq_ctx = zmq_ctx_new();
	ctx->zmq_sock = zmq_socket(ctx->zmq_ctx, ZMQ_REQ);
	snprintf(uri, MAX_ADDRESS_LEN, "tcp://%s:%d",
			ctx->conf.address, ctx->conf.port);
	return zmq_connect(ctx->zmq_sock, uri);
}

static void get_report(struct errgen_ctx *ctx, struct monitor_pkt_s *pkt)
{
	struct timeval tv = {0};

	gettimeofday(&tv, NULL);
	pkt->pid = ctx->pid;
	pkt->errcode = ctx->cnt++;
	pkt->tv_sec = tv.tv_sec;
	pkt->tv_usec = tv.tv_usec;
	memcpy(pkt->detector, ctx->conf.uuid, MAX_UUID_LEN);
}

static int send_report(struct errgen_ctx *ctx, struct monitor_pkt_s *pkt)
{
	char buf[sizeof(struct monitor_pkt_s)];

	debug("sending report #%d", ctx->cnt);
	marshall_monitor_pkt(pkt, buf);
	zmq_send(ctx->zmq_sock, buf, sizeof(struct monitor_pkt_s), 0);
	return 0;
}

static void errgen_loop(struct errgen_ctx *ctx)
{
	pid_t pid = getpid();
	struct monitor_pkt_s pkt;

	while (need_run) {
		get_report(ctx, &pkt);
		send_report(ctx, &pkt);
		sleep(ctx->conf.timeout);
	}
}

static void cleanup(struct errgen_ctx *ctx)
{
	if (ctx->zmq_sock) {
		zmq_close(ctx->zmq_sock);
	}
	if (ctx->zmq_ctx) {
		zmq_ctx_destroy(ctx->zmq_ctx);
	}
	if (ctx) {
		free(ctx);
	}
	closelog();
}

int main(int argc, char *argv[])
{
	struct errgen_ctx *ctx;

	ctx = (struct errgen_ctx *)malloc(sizeof(*ctx));
	if (!ctx) {
		fprintf(stderr, "ERROR: failed to allocate memory, exiting...\n");
		exit(1);
	}

	if (errgen_setup(ctx, argc, argv)) {
		cleanup(ctx);
		exit(2);
	}

	if (connect_to_server(ctx)) {
		debug("failed to establish connection with monitor at %s:%d...",
				ctx->conf.address, ctx->conf.port);
		cleanup(ctx);
		exit(3);
	}

	errgen_loop(ctx);

	info("terminating...");
	cleanup(ctx);

	return 0;
}
