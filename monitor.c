#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <zmq.h>
#include <getopt.h>
#include <pthread.h>

#include "common.h"
#include "log.h"
#include "msgproto.h"

#define MONITOR_DEFAULT_SYSLOGNAME  "monitor"
#define MONITOR_DEFAULT_TIMEOUT     20 // 20sec
#define MONITOR_DEFAULT_ERR_THRES   5

static int need_run = 1;

#define MAX_UUID_LEN    DETECTOR_SIZE
#define MAX_ADDRESS_LEN 64

#undef DEBUG_CTL

typedef enum monitor_action {
	MONITOR_ACTION_IGNORE = 0,
	MONITOR_ACTION_KILL,
	MONITOR_ACTION_GRACEFULL_KILL,
} monitor_action_t;

struct monitor_cfg {
	int port;
	int ctl_port;
	int timeout;
	int err_threshold;
	monitor_action_t action;
};

struct monitor_ctx;
struct client_s;

struct thread_arg {
	struct monitor_ctx *ctx;
	struct client_s *client;
};

struct client_s {
	char detector[DETECTOR_SIZE];
	int errcnt;
	pthread_t thread;
	struct thread_arg arg;
	int need_run;
	TAILQ_ENTRY(client_s) next;
};

typedef TAILQ_HEAD(head, client_s) client_list_t;

struct monitor_ctx {
	struct monitor_cfg conf;
	void *zmq_ctx;
	void *zmq_sock;
	void *zmq_ctl_sock;
	pthread_mutex_t mutex;
	client_list_t clients;
};

static void print_version(const char *argv0) {
	printf(
		"%s v.1.0 error monitor\n"
		"Demonstrates the libzmq usage\n", argv0);
}

static void print_help(const char *argv0) {
	printf(
		"%s [options]\n"
		"    -h --help                   Show this help\n"
		"    -v --version                Show version\n"
		"    -p --port=NUM               Set monitor port\n"
		"    -t --timeout=NUM            Set timeout (secs) to take corrective action\n"
		"    -e --err-threshold=NUM      Set threshold value for number of errors per client\n"
		"    -a --action={kill|ignore}   Set default corrective action for client\n"
		"    -g --debug                  Increase output verbosity\n"
		"\n", argv0);
}

static int parse_command_line(struct monitor_cfg *cfg,
		int argc, char *argv[]) {
	int opt, len;
	static const struct option long_options[] = {
		{ "version",		no_argument,		NULL, 'v' },
		{ "help",			no_argument,		NULL, 'h' },
		{ "debug",			no_argument,		NULL, 'g' },
		{ "port",			required_argument,	NULL, 'p' },
		{ "ctl-port",		required_argument,	NULL, 'c' },
		{ "timeout",		required_argument,	NULL, 't' },
		{ "err-threshold",	required_argument,	NULL, 'e' },
		{ "action",			required_argument,	NULL, 'a' },
		{ NULL, 0, NULL, 0 }
	};

	while ((opt = getopt_long(argc, argv, "vhg:pctea:",
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

		case 'g':
			verbosity++;
			break;

		case 'p':
			cfg->port = atoi(optarg);
			break;

		case 'c':
			cfg->ctl_port = atoi(optarg);
			break;

		case 't':
			cfg->timeout = atoi(optarg);
			break;

		case 'a':
			if (!strcmp(optarg, "kill")) {
				cfg->action = MONITOR_ACTION_KILL;
			}
			if (!strcmp(optarg, "gkill")) {
				cfg->action = MONITOR_ACTION_GRACEFULL_KILL;
			}
			else if (!strcmp(optarg, "ignore")) {
				cfg->action = MONITOR_ACTION_IGNORE;
			}
			else {
				fprintf(stderr, "ERROR: unknown action '%s'\n", optarg);
				return -1;
			}
			break;

		case 'e':
			cfg->err_threshold = atoi(optarg);
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

static int monitor_cfg_init(struct monitor_cfg *cfg)
{
	cfg->port = DEFAULT_PORT;
	cfg->ctl_port = DEFAULT_CTL_PORT;
	cfg->timeout = MONITOR_DEFAULT_TIMEOUT;
	cfg->action = MONITOR_ACTION_KILL;
	cfg->err_threshold = MONITOR_DEFAULT_ERR_THRES;
	return 0;
}

static void monitor_sig_handler(int sig)
{
	if (sig == SIGTERM || sig == SIGINT) {
		need_run = 0;
		info("cathed signal %d", sig);
	}
}

static int monitor_register_sighandlers(void)
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

	act.sa_handler = monitor_sig_handler;
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

static int setup_mutex(struct monitor_ctx *ctx)
{
	int ret;

	ret = pthread_mutex_init(&ctx->mutex, NULL);
	if (ret) {
		error("pthread_mutex_init(): %s", strerror(ret));
		return 1;
	}
	return 0;
}

static int monitor_setup(struct monitor_ctx *ctx, int argc, char *argv[])
{
	if (monitor_cfg_init(&ctx->conf)) {
		fprintf(stderr, "ERROR: unrecoverable error\n");
		return -1;
	}

	if (parse_command_line(&ctx->conf, argc, argv)) {
		fprintf(stderr, "Type '--help' for more information\n");
		return -1;
	}

	if (monitor_register_sighandlers()) {
		fprintf(stderr, "ERROR: failed to register signal handlers\n");
		return -1;
	}

	openlog(MONITOR_DEFAULT_SYSLOGNAME, LOG_PID|LOG_CONS, LOG_DAEMON);

	info("  port: %d", ctx->conf.port);
	info("  control port: %d", ctx->conf.ctl_port);
	info("  timeout: %d", ctx->conf.timeout);
	info("  action: %d", ctx->conf.action);
	info("  err-threshold: %d", ctx->conf.err_threshold);

	TAILQ_INIT(&ctx->clients);
	setup_mutex(ctx);

	return 0;
}

static int setup_connection(struct monitor_ctx *ctx)
{
	char uri[MAX_ADDRESS_LEN];
	int rv;

	ctx->zmq_ctx = zmq_ctx_new();
	if (!ctx->zmq_ctx) {
		error("failed to create zmq context");
		return -1;
	}

	ctx->zmq_sock = zmq_socket(ctx->zmq_ctx, ZMQ_PULL);
	if (!ctx->zmq_sock) {
		error("failed to create zmq socket");
		return -1;
	}

	ctx->zmq_ctl_sock = zmq_socket(ctx->zmq_ctx, ZMQ_PUB);
	if (!ctx->zmq_ctl_sock) {
		error("failed to create zmq control socket");
		return -1;
	}

	info("Start listening on port %d...", ctx->conf.port);
	snprintf(uri, MAX_ADDRESS_LEN, "tcp://*:%d", ctx->conf.port);
	rv = zmq_bind(ctx->zmq_sock, uri);
	if (!rv) {
		info("Start listening on control port %d...", ctx->conf.ctl_port);
		snprintf(uri, MAX_ADDRESS_LEN, "tcp://*:%d", ctx->conf.ctl_port);
		rv |= zmq_bind(ctx->zmq_ctl_sock, uri);
	}

	return rv;
}

static int receive_report(struct monitor_ctx *ctx, struct monitor_pkt_s *pkt)
{
	char buf[512];
	int rv;

	zmq_pollitem_t items[] = {
		{ ctx->zmq_sock, 0, ZMQ_POLLIN, 0 },
	};

	zmq_poll(items, 1, ZMQ_POLL_TIMEOUT_MAX);
	if (items[0].revents & ZMQ_POLLIN) {
		rv = zmq_recv(ctx->zmq_sock, buf, sizeof(*pkt), 0);
		if (rv == sizeof(*pkt)) {
			dump_raw_pkt(buf,  sizeof(*pkt));
			unmarshall_monitor_pkt(buf, pkt);
			info("got report from [%s] --> %d", pkt->detector, pkt->errcode);
			return 1;
		}
	}

	return 0;
}

static void check_client(struct monitor_ctx *ctx,
		struct client_s *client)
{
	struct monitor_ctl_pkt_s ctlpkt;
	char msg[sizeof(struct monitor_ctl_pkt_s)];

	if (client->errcnt > ctx->conf.err_threshold) {
		info("taking care of client uuid=%s", client->detector);

		switch (ctx->conf.action) {
		case MONITOR_ACTION_IGNORE:
			info("ignoring error rate from client uuid=%s", client->detector);
			break;

		case MONITOR_ACTION_KILL:
			ctlpkt.command = MONITOR_CMD_KILL;
			memcpy(ctlpkt.detector, client->detector, sizeof(ctlpkt.detector));
			marshall_monitor_ctl_pkt(&ctlpkt, msg);
			info("kill client uuid=%s", client->detector);
			zmq_send(ctx->zmq_ctl_sock, msg, sizeof(ctlpkt), 0);
			client->need_run = 0;
			break;

		case MONITOR_ACTION_GRACEFULL_KILL:
			ctlpkt.command = MONITOR_CMD_GRACEFULL_KILL;
			memcpy(ctlpkt.detector, client->detector, sizeof(ctlpkt.detector));
			marshall_monitor_ctl_pkt(&ctlpkt, msg);
			info("gracefully kill client uuid=%s", client->detector);
			zmq_send(ctx->zmq_ctl_sock, msg, sizeof(ctlpkt), 0);
			client->need_run = 0;
			break;

		default:
			break;
		}
	}

	info("clearing errcnt for client %s", client->detector);
	client->errcnt = 0;
}

static void *client_monitor(void *arg)
{
	struct thread_arg *targ = (struct thread_arg *)arg;
	struct client_s *client = targ->client;
	struct monitor_ctx *ctx = targ->ctx;
	int ret;

	while (need_run && client->need_run) {
		sleep(ctx->conf.timeout);
		check_client(ctx, client);
	}

	info("leaving monitor for client %s...", client->detector);

	return NULL;
}

static struct client_s *add_client(struct monitor_ctx *ctx, struct monitor_pkt_s *pkt)
{
	struct client_s *client;

	client = (struct client_s *)malloc(sizeof(*client));
	if (!client) {
		info("failed to add new client uuid=%s", pkt->detector);
		return NULL;
	}
	client->arg.client = client;
	client->arg.ctx = ctx;
	client->need_run = 1;

	memcpy(client->detector, pkt->detector, sizeof(client->detector));
	client->errcnt = 0;

	TAILQ_INSERT_TAIL(&ctx->clients, client, next);

	pthread_create(&client->thread, NULL, client_monitor, &client->arg);

	return client;
}

static void remove_client(struct monitor_ctx *ctx, struct client_s *client)
{
	int ret;

	info("removing client %s", client->detector);
	ret = pthread_join(client->thread, NULL);
	if (ret) {
		error("pthread_join(): %s", strerror(ret));
	}
	TAILQ_REMOVE(&ctx->clients, client, next);
	free(client);
}

static int process_report(struct monitor_ctx *ctx, struct monitor_pkt_s *pkt)
{
	int not_processed = 1, ret;
	struct client_s *client;

	ret = pthread_mutex_lock(&ctx->mutex);
	if (ret) {
		error("pthread_mutex_lock(): %s", strerror(ret));
		return 1;
	}

	if (!TAILQ_EMPTY(&ctx->clients)) {
		TAILQ_FOREACH(client, &ctx->clients, next) {
			if (!client->need_run) {
				not_processed = 0;
				break;
			}
			if (!strncmp(client->detector, pkt->detector, sizeof(client->detector))) {
				client->errcnt++;
				not_processed = 0;
				info("processing client %s:%d (errcnt=%d)", client->detector, pkt->errcode, client->errcnt);
			}
		}
	}

	if (not_processed) {
		info("adding client [%s]", pkt->detector);
		client = add_client(ctx, pkt);
		if (client) {
			client->errcnt++;
			not_processed = 0;
		}
	}
	pthread_mutex_unlock(&ctx->mutex);

#if DEBUG_CTL
	{
		struct monitor_ctl_pkt_s ctlpkt;
		char msg[sizeof(struct monitor_ctl_pkt_s)];

		ctlpkt.command = MONITOR_CMD_DUMMY;
		memcpy(ctlpkt.detector, pkt->detector, sizeof(ctlpkt.detector));
		marshall_monitor_ctl_pkt(&ctlpkt, msg);
		info("dummy command for client uuid=%s", pkt->detector);
		zmq_send(ctx->zmq_ctl_sock, &ctlpkt, sizeof(ctlpkt), 0);
	}
#endif

	return !not_processed;
}

static void check_clients(struct monitor_ctx *ctx)
{
	int ret;
	struct client_s *client;

	ret = pthread_mutex_lock(&ctx->mutex);
	if (ret) {
		error("pthread_mutex_lock(): %s", strerror(ret));
		return;
	}

	if (!TAILQ_EMPTY(&ctx->clients)) {
		TAILQ_FOREACH(client, &ctx->clients, next) {
			if (!client->need_run) {
				remove_client(ctx, client);
			}
		}
	}

	pthread_mutex_unlock(&ctx->mutex);
}

static void monitor_loop(struct monitor_ctx *ctx)
{
	struct monitor_pkt_s pkt;

	while (need_run) {
		if (receive_report(ctx, &pkt)) {
			process_report(ctx, &pkt);
		}
		check_clients(ctx);
	}
}

static void cleanup(struct monitor_ctx *ctx)
{
	struct client_s *client;
	int ret;

	if (ctx->zmq_ctl_sock) {
		zmq_close(ctx->zmq_ctl_sock);
	}
	if (ctx->zmq_sock) {
		zmq_close(ctx->zmq_sock);
	}
	if (ctx->zmq_ctx) {
		zmq_ctx_destroy(ctx->zmq_ctx);
	}

	if (!TAILQ_EMPTY(&ctx->clients)) {
		TAILQ_FOREACH(client, &ctx->clients, next) {
			client->need_run = 0;
		}
		TAILQ_FOREACH(client, &ctx->clients, next) {
			remove_client(ctx, client);
		}
	}

	if (ctx) {
		free(ctx);
	}
	closelog();
}

int main(int argc, char *argv[])
{
	struct monitor_ctx *ctx;

	ctx = (struct monitor_ctx *)malloc(sizeof(*ctx));
	if (!ctx) {
		fprintf(stderr, "ERROR: failed to allocate memory, exiting...\n");
		exit(1);
	}

	if (monitor_setup(ctx, argc, argv)) {
		cleanup(ctx);
		exit(2);
	}

	if (setup_connection(ctx)) {
		debug("failed to setup connection on port %d...", ctx->conf.port);
		cleanup(ctx);
		exit(3);
	}

	monitor_loop(ctx);

	info("terminating...");
	cleanup(ctx);

	return 0;
}

