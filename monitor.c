#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <zmq.h>
#include <getopt.h>
#include <syslog.h>
#include <pthread.h>

#include "msgproto.h"

#define MONITOR_DEFAULT_SYSLOGNAME  "monitor"
#define MONITOR_DEFAULT_TIMEOUT     20000 // 20sec
#define MONITOR_DEFAULT_ERR_THRES   5

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

void __attribute__((__format__(__printf__,1,2)))
error(const char *fmt, ...)
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

typedef enum monitor_action {
	MONITOR_ACTION_KILL   = 0,
	MONITOR_ACTION_IGNORE = 1,
} monitor_action_t;

struct monitor_cfg {
	int port;
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
	int pid;
	int time_window;
	int errcnt;
	pthread_t thread;
	struct thread_arg arg;
	TAILQ_ENTRY(client_s) next;
};

typedef TAILQ_HEAD(head, client_s) client_list_t;

struct monitor_ctx {
	struct monitor_cfg conf;
	void *zmq_ctx;
	void *zmq_sock;
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
		"    -t --timeout=NUM            Set timeout to take corrective action\n"
		"    -e --err-threshold=NUM      Set threshold value for number of errors per client\n"
		"    -a --action={kill|ignore}   Set default corrective action for client\n"
		"    -d --debug                  Increase output verbosity\n"
		"\n", argv0);
}

static int parse_command_line(struct monitor_cfg *cfg,
		int argc, char *argv[]) {
	int opt, len;
	static const struct option long_options[] = {
		{ "version",		no_argument,		NULL, 'v' },
		{ "help",			no_argument,		NULL, 'h' },
		{ "debug",			no_argument,		NULL, 'd' },
		{ "port",			optional_argument,	NULL, 'p' },
		{ "timeout",		optional_argument,	NULL, 't' },
		{ "err-threshold",	optional_argument,	NULL, 'e' },
		{ "action",			optional_argument,	NULL, 'a' },
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

		case 'p':
			cfg->port = atoi(optarg);
			break;

		case 't':
			cfg->port = atoi(optarg);
			break;

		case 'a':
			if (!strcmp(optarg, "kill")) {
				cfg->action = MONITOR_ACTION_KILL;
			}
			else if (!strcmp(optarg, "ignore")) {
				cfg->action = MONITOR_ACTION_IGNORE;
			}
			else {
				fprintf(stderr, "ERROR: unknown action '%s'\n", optarg);
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

	info("Start listening on port %d...", ctx->conf.port);
	ctx->zmq_ctx = zmq_ctx_new();
	ctx->zmq_sock = zmq_socket(ctx->zmq_ctx, ZMQ_REQ);
	snprintf(uri, MAX_ADDRESS_LEN, "tcp://*:%d", ctx->conf.port);
	return zmq_bind(ctx->zmq_sock, uri);
}

static void receive_report(struct monitor_ctx *ctx, struct monitor_pkt_s *pkt)
{
	char buf[sizeof(struct monitor_pkt_s)];

	zmq_recv(ctx->zmq_sock, buf, sizeof(struct monitor_pkt_s), 0);
	unmarshall_monitor_pkt(buf, pkt);
}

static int take_corrective_action(struct monitor_ctx *ctx,
		struct client_s *client)
{
	if (client->errcnt > ctx->conf.err_threshold) {
		info("taking care of client pid=%d uuid=%s", client->pid, client->detector);

		if (ctx->conf.action == MONITOR_ACTION_KILL) {
			info("client pid=%d will be killed", client->pid);
			kill(client->pid, SIGKILL);
			return 0;
		}
	}

	return 1;
}

static void *client_monitor(void *arg)
{
	struct thread_arg *targ = (struct thread_arg *)arg;
	struct client_s *client = targ->client;
	struct monitor_ctx *ctx = targ->ctx;
	int ret;

	while (need_run) {
		sleep(ctx->conf.timeout);
		ret = pthread_mutex_lock(&ctx->mutex);
		if (ret) {
			error("pthread_mutex_lock(): %s", strerror(ret));
			return NULL;
		}

		if (take_corrective_action(ctx, client)) {
			TAILQ_REMOVE(&ctx->clients, client, next);
			free(client);
			break;
		}

		ret = pthread_mutex_lock(&ctx->mutex);
	}

	return NULL;
}

static struct client_s *add_new_client(struct monitor_ctx *ctx, struct monitor_pkt_s *pkt)
{
	struct client_s *client;

	client = (struct client_s *)malloc(sizeof(*client));
	if (!client) {
		info("failed to add new client pid=%d", pkt->pid);
		return NULL;
	}
	client->arg.client = client;
	client->arg.ctx = ctx;

	memcpy(client->detector, pkt->detector, sizeof(client->detector));
	client->errcnt = 0;
	client->pid = pkt->pid;
	client->time_window = ctx->conf.timeout;

	TAILQ_INSERT_TAIL(&ctx->clients, client, next);

	pthread_create(&client->thread, NULL, client_monitor, &client->arg);

	return client;
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

	TAILQ_FOREACH(client, &ctx->clients, next) {
		if (!strcmp(client->detector, pkt->detector)) {
			info("processing client %d -- errcnt=%d, time_window=%d",
					client->pid, client->errcnt, client->time_window);
			client->errcnt++;
			not_processed = 0;
		}
	}

	if (not_processed) {
		client = add_new_client(ctx, pkt);
		if (client) {
			client->errcnt++;
			not_processed = 0;
		}
	}

	pthread_mutex_unlock(&ctx->mutex);

	return !not_processed;
}

static void monitor_loop(struct monitor_ctx *ctx)
{
	struct monitor_pkt_s pkt;

	while (need_run) {
		receive_report(ctx, &pkt);
		process_report(ctx, &pkt);
	}
}

static void cleanup(struct monitor_ctx *ctx)
{
	struct client_s *client;
	int ret;

	if (ctx->zmq_sock) {
		zmq_close(ctx->zmq_sock);
	}
	if (ctx->zmq_ctx) {
		zmq_ctx_destroy(ctx->zmq_ctx);
	}

	while ((client = TAILQ_FIRST(&ctx->clients))) {
		ret = pthread_join(client->thread, NULL);
		if (ret) {
			error("pthread_join(): %s", strerror(ret));
		}

		TAILQ_REMOVE(&ctx->clients, client, next);
		free(client);
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

