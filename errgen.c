#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <zmq.h>
#include <getopt.h>
#include <pthread.h>

#include "common.h"
#include "log.h"
#include "msgproto.h"

#define ERRGEN_DEFAULT_SYSLOGNAME  "errgen"
#define ERRGEN_DEFAULT_TIMEOUT     5 // 5sec

static int need_run = 1;

#define MAX_UUID_LEN    DETECTOR_SIZE
#define MAX_ADDRESS_LEN 64

struct errgen_cfg {
	int port;
	int ctl_port;
	char address[MAX_ADDRESS_LEN];
	char uuid[MAX_UUID_LEN];
	int timeout;
};

struct errgen_ctx {
	struct errgen_cfg conf;
	void *zmq_ctx;
	void *zmq_sock;
	void *zmq_ctl_sock;
	int cnt;
	pthread_t ctl_thread;
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
		"    -c --ctl-port=NUM        Set monitor control port\n"
		"    -a --address=ADDR        Set monitor hostname\n"
		"    -u --uuid=STRING         Set UUID of the client\n"
		"    -t --timeout=NUM         Set timeout (secs) to generate err report\n"
		"    -g --debug               Increase output verbosity\n"
		"\n", argv0);
}

static int parse_command_line(struct errgen_cfg *cfg,
		int argc, char *argv[]) {
	int opt, len;
	const struct option long_options[] = {
		{ "version",	no_argument,		NULL, 'v' },
		{ "help",		no_argument,		NULL, 'h' },
		{ "debug",		no_argument,		NULL, 'g' },
		{ "uuid",		required_argument,	NULL, 'u' },
		{ "port",		required_argument,	NULL, 'p' },
		{ "ctl-port",	required_argument,	NULL, 'c' },
		{ "address",	required_argument,	NULL, 'a' },
		{ "timeout",	required_argument,	NULL, 't' },
		{ NULL, 0, NULL, 0 }
	};

	if (argc < 2) {
		print_help(argv[0]);
		exit(0);
	}

	while ((opt = getopt_long(argc, argv, "vhg:upat:",
			long_options, NULL)) != -1) {
		switch(opt) {
		case 'h':
			print_help(argv[0]);
			exit(0);
			break;

		case 'v':
			print_version(argv[0]);
			exit(0);
			break;

		case 'g':
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

		case 'c':
			cfg->ctl_port = atoi(optarg);
			break;

		case 'a':
			len = strlen(optarg);
			if (len > MAX_ADDRESS_LEN) {
				len = MAX_ADDRESS_LEN;
			}
			memcpy(cfg->address, optarg, len);
			break;

		case 't':
			cfg->timeout = atoi(optarg);
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
	cfg->ctl_port = DEFAULT_CTL_PORT;
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
	info("  control port: %d", ctx->conf.ctl_port);
	info("  uuid: %s", ctx->conf.uuid);
	info("  timeout: %d", ctx->conf.timeout);

	return 0;
}

static int connect_to_server(struct errgen_ctx *ctx)
{
	char uri[MONITOR_MAX_STR_SZ];
	int rv;

	info("Connecting to monitor at %s:%d...",
			ctx->conf.address, ctx->conf.port);

	ctx->zmq_ctx = zmq_ctx_new();
	if (!ctx->zmq_ctx) {
		error("failed to create zmq context");
		return -1;
	}

	ctx->zmq_sock = zmq_socket(ctx->zmq_ctx, ZMQ_REQ);
	if (!ctx->zmq_sock) {
		error("failed to create zmq socket");
		return -1;
	}

	ctx->zmq_ctl_sock = zmq_socket(ctx->zmq_ctx, ZMQ_SUB);
	if (!ctx->zmq_ctl_sock) {
		error("failed to create zmq control socket");
		return -1;
	}
	zmq_setsockopt(ctx->zmq_ctl_sock, ZMQ_SUBSCRIBE, NULL, 0);

	snprintf(uri, MONITOR_MAX_STR_SZ, "tcp://%s:%d",
			ctx->conf.address, ctx->conf.port);
	rv = zmq_connect(ctx->zmq_sock, uri);
	debug("packet --> zmq_connect(%s): %d", uri, rv);

	if (!rv) {
		snprintf(uri, MONITOR_MAX_STR_SZ, "tcp://%s:%d",
				ctx->conf.address, ctx->conf.ctl_port);
		rv |= zmq_connect(ctx->zmq_ctl_sock, uri);
		debug("control --> zmq_connect(%s): %d", uri, rv);
	}

	return rv;
}

static int receive_command(struct errgen_ctx *ctx, struct monitor_ctl_pkt_s *pkt)
{
	char buf[sizeof(struct monitor_ctl_pkt_s)];
	int rv;
	struct monitor_ctl_rsp_pkt_s rsp;

	info("listening for command");
	zmq_recv(ctx->zmq_ctl_sock, buf, sizeof(*pkt), 0);

		unmarshall_monitor_ctl_pkt(buf, pkt);
		info("received command %d", pkt->command);
		dump_raw_pkt(buf, sizeof(*pkt));

		return 1;

}

static int process_command(struct errgen_ctx *ctx, struct monitor_ctl_pkt_s *pkt)
{
	if (pkt->command == -1) {
		return 1;
	}

	switch (pkt->command) {
	case MONITOR_CMD_DUMMY:
		info("processed MONITOR_CMD_DUMMY");
		break;

	case MONITOR_CMD_GRACEFULL_KILL:
		need_run = 0;
		info("processed MONITOR_CMD_GRACEFULL_KILL -- will shutdown!!!");
		break;

	case MONITOR_CMD_KILL:
		info("processed MONITOR_CMD_KILL -- use brute force, will shutdown!!!");
		kill(getpid(), SIGKILL);
		break;

	default:
		debug("unknown command %d", pkt->command);
		return 1;
	}

	return 0;
}

static void *errgen_ctl_thread(void *arg)
{
	struct errgen_ctx *ctx = (struct errgen_ctx *)arg;
	struct monitor_ctl_pkt_s pkt;

	while (need_run) {
		pkt.command = -1;
		if (receive_command(ctx, &pkt)) {
			process_command(ctx, &pkt);
		}
	}
	info("exiting control thread...");

	return NULL;
}

static void errgen_start_ctl_loop(struct errgen_ctx *ctx)
{
	pthread_create(&ctx->ctl_thread, NULL, errgen_ctl_thread, ctx);
}

static void get_report(struct errgen_ctx *ctx, struct monitor_pkt_s *pkt)
{
	struct timeval tv = {0};

	gettimeofday(&tv, NULL);
	pkt->errcode = ctx->cnt++;
	pkt->tv_sec = tv.tv_sec;
	pkt->tv_usec = tv.tv_usec;
	memcpy(pkt->detector, ctx->conf.uuid, sizeof(ctx->conf.uuid));
}

static void send_report(struct errgen_ctx *ctx, struct monitor_pkt_s *pkt)
{
	char buf[sizeof(struct monitor_pkt_s)];
	struct monitor_rsp_pkt_s rsp;

	debug("sending report #%d", ctx->cnt);
	marshall_monitor_pkt(pkt, buf);
	dump_raw_pkt(buf, sizeof(*pkt));
	zmq_send(ctx->zmq_sock, buf, sizeof(*pkt), 0);

	zmq_recv(ctx->zmq_sock, buf, sizeof(rsp), 0);
	unmarshall_monitor_rsp_pkt(buf, &rsp);

	if (rsp.response == MONITOR_RSP_OK &&
			!strncmp(rsp.detector, pkt->detector, sizeof(rsp.detector))) {
		info("report %d received", rsp.errcode);
	}

}

static void errgen_loop(struct errgen_ctx *ctx)
{
	pid_t pid = getpid();
	struct monitor_pkt_s pkt;

	errgen_start_ctl_loop(ctx);
	while (need_run) {
		get_report(ctx, &pkt);
		send_report(ctx, &pkt);
		sleep(ctx->conf.timeout);
	}
}

static void cleanup(struct errgen_ctx *ctx)
{
	if (!pthread_join(ctx->ctl_thread, NULL)) {
		error("pthread_join()");
	}
	if (ctx->zmq_sock) {
		zmq_close(ctx->zmq_sock);
	}
	if (ctx->zmq_ctl_sock) {
		zmq_close(ctx->zmq_ctl_sock);
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
	struct errgen_ctx *ctx = NULL;

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
