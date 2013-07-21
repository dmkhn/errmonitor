/*
 *   errgen.c - Error report generator
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
#include "monitorpkt.h"

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

	while ((opt = getopt_long(argc, argv, "vhg:u:p:a:t:",
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

	if (!strcmp(cfg->uuid, "")) {
		fprintf(stderr, "ERROR: uuid is not set\n");
		return -1;
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
	int ltimeout = ZMQ_LINGER_TIMEOUT_MAX;

	info("Connecting to monitor at %s:%d...",
			ctx->conf.address, ctx->conf.port);

	ctx->zmq_ctx = zmq_ctx_new();
	if (!ctx->zmq_ctx) {
		error("failed to create zmq context");
		return -1;
	}

	ctx->zmq_sock = zmq_socket(ctx->zmq_ctx, ZMQ_PUSH);
	if (!ctx->zmq_sock) {
		error("failed to create zmq socket");
		return -1;
	}

	/* NB: Need to setup linger timeout in order to terminate the process
	 * correctly: zmq_ctx_destroy() will block until all messages sent over
	 * the socket were *delivered* to the destination. In case of server
	 * is down, this will cause endless timeout in zmq_ctx_destroy(). */
	zmq_setsockopt(ctx->zmq_sock, ZMQ_LINGER, &ltimeout, sizeof(ltimeout));

	ctx->zmq_ctl_sock = zmq_socket(ctx->zmq_ctx, ZMQ_SUB);
	if (!ctx->zmq_ctl_sock) {
		error("failed to create zmq control socket");
		return -1;
	}
	zmq_setsockopt(ctx->zmq_ctl_sock, ZMQ_SUBSCRIBE, "", 0);

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

static int receive_command(struct errgen_ctx *ctx,
		struct monitor_ctl_pkt_s *pkt)
{
	char buf[sizeof(struct monitor_ctl_pkt_s)];
	int rv;
	zmq_pollitem_t items[] = {
		{ ctx->zmq_ctl_sock, 0, ZMQ_POLLIN, 0 },
	};

	zmq_poll(items, 1, ZMQ_POLL_CTL_TIMEOUT_MAX);
	if (items[0].revents & ZMQ_POLLIN) {
		rv = zmq_recv(ctx->zmq_ctl_sock, buf, sizeof(*pkt), 0);
		if (rv == sizeof(*pkt)) {
			unmarshall_monitor_ctl_pkt(buf, pkt);
			debug("received command %d for client %s",
					pkt->command, pkt->detector);
			dump_raw_pkt(buf, sizeof(*pkt));
			return 1;
		}
	}

	return 0;
}

static int process_command(struct errgen_ctx *ctx,
		struct monitor_ctl_pkt_s *pkt)
{
	if (strncmp(pkt->detector, ctx->conf.uuid, sizeof(pkt->detector))) {
		debug("ignoring command request for %s", pkt->detector);
		return 1;
	}

	switch (pkt->command) {
	case MONITOR_CMD_DUMMY:
		info("processed MONITOR_CMD_DUMMY by client %s", ctx->conf.uuid);
		break;

	case MONITOR_CMD_GRACEFULL_KILL:
		need_run = 0;
		info("processed MONITOR_CMD_GRACEFULL_KILL by client %s -- will shutdown!!!",
				ctx->conf.uuid);
		break;

	case MONITOR_CMD_KILL:
		info("processed MONITOR_CMD_KILL by client %s -- use brute force, will shutdown!!!",
				ctx->conf.uuid);
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

	info("entering control loop");
	while (need_run) {
		if (receive_command(ctx, &pkt)) {
			if (!process_command(ctx, &pkt)) {
				info("failed to process command %d for client %s",
						pkt.command, pkt.detector);
			}
		}
	}
	info("exiting control thread...");

	return NULL;
}

static void errgen_start_ctl_loop(struct errgen_ctx *ctx)
{
	int ret;

	ret = pthread_create(&ctx->ctl_thread, NULL, errgen_ctl_thread, ctx);
	if (ret) {
		error("failed to create control thread err=%s", strerror(ret));
		need_run = 0;
	}
}

static void get_report(struct errgen_ctx *ctx, struct monitor_pkt_s *pkt)
{
	pkt->errcode = ctx->cnt;
	memcpy(pkt->detector, ctx->conf.uuid, sizeof(ctx->conf.uuid));
}

static void send_report(struct errgen_ctx *ctx, struct monitor_pkt_s *pkt)
{
	char buf[512];

	info("sending report #%d", ctx->cnt);
	marshall_monitor_pkt(pkt, buf);
	dump_raw_pkt(buf, sizeof(*pkt));

	zmq_send(ctx->zmq_sock, buf, sizeof(*pkt), ZMQ_DONTWAIT);
	ctx->cnt++;
}

static void errgen_loop(struct errgen_ctx *ctx)
{
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
	pthread_join(ctx->ctl_thread, NULL);
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
