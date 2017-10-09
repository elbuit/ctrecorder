/*
 *
 *
 *
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netdb.h>


#include "ctrecorder.h"
#include "util.h"
#include "daemon.h"


#define HASH_SIZE		65536

/* constants */
const int nftype_map[] = {
	[NF_NETLINK_CONNTRACK_NEW] = NF_NEW,
	[NF_NETLINK_CONNTRACK_UPDATE] = NF_UPDATE,
	[NF_NETLINK_CONNTRACK_DESTROY] = NF_DESTROY,
};

const char* nftype_name[] = {
	[NF_RESERVED] = "R",
	[NF_NEW] = "S",
	[NF_UPDATE] = "U",
	[NF_DESTROY] = "E",
};



/* file name template */
int fd = -1;
char *fnt = NULL;
struct common *buffer = NULL;
int buffer_pos = 0;
/* rotation, squeeze */
int last_rotation_time = 0;
int rotation_interval = 0;
int auto_squeeze = 0;
int hide_header = 0;
int buffer_size = 100;
int protocol = IPPROTO_TCP;
/* system */
int priority = 0;
char *user = NULL;
char *group = NULL;
char *pid_file = NULL;	// "/var/run/ctrecorder.pid";
/* netfilter */
struct nfct_handle *cth = NULL;
int nfnl_buffer_size = 0;
/* statistics */

struct {
	time_t started;
	time_t restarted;
	time_t rotated;

	llu received;
	llu saved;
	llu flushed;
	llu rotations;
	llu rotation_fails;
	llu write_errors;
	llu catch;
} stats;


/* functions */

void log_stats()
{
	log_action(LOG_INFO, "received=%llu, saved=%llu, flushed=%llu, rotations=%llu, rotation_fails=%llu, write_errors=%llu, catch=%llu",
		stats.received, stats.saved, stats.flushed, stats.rotations, stats.rotation_fails, stats.write_errors, stats.catch);
}


/* thread NON SAFE */
char* ltime(time_t t)
{
	struct tm stm;
	static char ts[32];

	localtime_r(&t, &stm);
	strftime(ts, sizeof(ts), "%Y.%m.%d %H:%M:%S", &stm);
	TERMINATE_STRING(ts);

	return ts;
}

/* thread NON SAFE */
char* protoname(int protonum)
{
	struct protoent *p;

	if ((p = getprotobynumber(protonum)) == NULL)
		return "?";

	return p->p_name;
}

void buffer_flush();

void cleanup()
{
#ifndef DISABLE_CAPTURE
	if (cth)
		nfct_close(cth);
#endif

	buffer_flush();
	SAFE_CLOSE(fd);
	pidfile_remove(pid_file);
}


void new_file(struct timeval *);

void signal_handler(int sig)
{
	switch (sig) {
		case SIGHUP:
			new_file(NULL);
			stats.restarted = time(NULL);
			break;
		case SIGUSR1:
			buffer_flush();
			log_stats();
			break;
		case SIGUSR2:
			break;
		case SIGTERM:
		case SIGINT:
		case SIGQUIT:
		default:
			log_action(LOG_CRIT, "got signal %s, quitting", strsignal(sig));
			cleanup();
			log_stats();
			exit(0);
	}
}


void show_event_common(struct common e)
{
	printf("%s.%06u", ltime(ntohl(e.time.sec)), ntohl(e.time.usec));
	printf(" %s%s", nftype_name[e.type & NF_BITMASK], IS_FLAG_SET(e.type, FLAG_REPLIED) ? "+" : " ");
	printf(" src=%d.%d.%d.%d:%d", NIPQUAD(e.addr.orig.src.ip), ntohs(e.addr.orig.src.port));
	printf(" dst=%d.%d.%d.%d:%d", NIPQUAD(e.addr.orig.dst.ip), ntohs(e.addr.orig.dst.port));
	printf(" src=%d.%d.%d.%d:%d", NIPQUAD(e.addr.repl.src.ip), ntohs(e.addr.repl.src.port));
	printf(" dst=%d.%d.%d.%d:%d", NIPQUAD(e.addr.repl.dst.ip), ntohs(e.addr.repl.dst.port));
	printf("\n");
}

void show_event_combined(struct combined e)
{
	const char* nodate = "-          -              ";

	if (ntohl(e.create.sec)) {
		printf("%s.%06u", ltime(ntohl(e.create.sec)), ntohl(e.create.usec));
	} else {
		printf(nodate);
	}
	printf(" ");
	if (ntohl(e.destroy.sec)) {
		printf("%s.%06u", ltime(ntohl(e.destroy.sec)), ntohl(e.destroy.usec));
	} else {
		printf(nodate);
	}

	printf(" src=%d.%d.%d.%d:%d", NIPQUAD(e.addr.orig.src.ip), ntohs(e.addr.orig.src.port));
	printf(" dst=%d.%d.%d.%d:%d", NIPQUAD(e.addr.orig.dst.ip), ntohs(e.addr.orig.dst.port));
	printf(" src=%d.%d.%d.%d:%d", NIPQUAD(e.addr.repl.src.ip), ntohs(e.addr.repl.src.port));
	printf(" dst=%d.%d.%d.%d:%d", NIPQUAD(e.addr.repl.dst.ip), ntohs(e.addr.repl.dst.port));
	printf("\n");
}

/* collecting events */
void new_file(struct timeval *tv)
{
	struct file_header fh;
	struct timeval tv_buf;
	struct timezone tz;
	struct tm stm;
	char fn[1024];
	int res, nfd;

	/* initialize header */
	memset(&fh, 0, sizeof(fh));
	fh.magic = htonl(CTEVENTLOG_MAGIC);
	fh.version = htonl(CTEVENTLOG_VERSION);
	fh.fhlen = htons(sizeof(fh));
	fh.entrylen = htons(sizeof(struct common));
	fh.fflen = htons(0);
	fh.proto = protocol;

	/* get hostname */
	gethostname(fh.hostname, sizeof(fh.hostname));
	TERMINATE_STRING(fh.hostname);

	/* extract timezone */
	gettimeofday(&tv_buf, &tz);
	if (!tv) tv = &tv_buf;
	fh.start_time.sec = htonl(tv->tv_sec);
	fh.start_time.usec = htonl(tv->tv_usec);
	fh.start_tz.minuteswest = htonl(tz.tz_minuteswest);
	fh.start_tz.dsttime = htonl(tz.tz_dsttime);


	struct tm tmm;
	localtime_r(&tv->tv_sec, &tmm);
	fh.utc_offset = htonl(tmm.tm_gmtoff);
	fh.start_time_dec.year = htons(tmm.tm_year);
	fh.start_time_dec.month = tmm.tm_mon;
	fh.start_time_dec.day = tmm.tm_mday;
	fh.start_time_dec.hour = tmm.tm_hour;
	fh.start_time_dec.min = tmm.tm_min;
	fh.start_time_dec.sec = tmm.tm_sec;


	/* prepare new filename */
	localtime_r(&tv->tv_sec, &stm);
	strftime(fn, sizeof(fn), fnt, &stm);
	TERMINATE_STRING(fn);

	// 0660?
	if ((nfd = open(fn, O_CREAT|O_WRONLY|O_EXCL|O_NOCTTY, 0666)) == -1) {
		log_action(LOG_ERR, "open(%s): %s", fn, strerror(errno));
		if (fd == -1) {
			cleanup();
			exit(1);
		}
	
		log_action(LOG_WARNING, "... writing still to old file");
		/* give up till next try */
		last_rotation_time = tv->tv_sec;
		stats.rotation_fails++;
		return;
	}

	log_action(LOG_INFO, "recording to %s", fn);
	if ((res = safe_write(nfd, &fh, sizeof(fh))) == -1) {
		log_action(LOG_ERR, "write(%s): %s", fn, strerror(errno));
		cleanup();
		log_stats();
		exit(1);
	}

	if (fd != -1) {
		stats.rotations++;
		stats.rotated = time(NULL);
		buffer_flush();
		log_stats();
		SAFE_CLOSE(fd);
		// if (auto_squeeze) fork(), close(...), nice(-19), sleep(5), squeeze(old_fn)
	}

	fd = nfd;
	last_rotation_time = tv->tv_sec;

	// combine old file to other format
	// fork(); close(); ...

}

void buffer_flush()
{
	int res;

	if (fd == -1 || !buffer_pos)
		return;

	if ((res = safe_write(fd, buffer, buffer_pos * sizeof(*buffer))) == -1) {
		log_action(LOG_ERR, "write(%d): %s", buffer_pos, strerror(errno));
		stats.write_errors += buffer_pos;
	} else {
//		log_action(LOG_DEBUG | LOG_FORE_ONLY, "write(%d): %d", buffer_pos, res);
		stats.flushed += buffer_pos;
	}

	buffer_pos = 0;
}

#ifndef DISABLE_CAPTURE
int event(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data)
{
	struct timeval tv;

	stats.received++;
	if (nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO) != protocol)
		return NFCT_CB_CONTINUE;

#ifdef OFF_HAVE_DECL_ATTR_TIMESTAMP_START
	if (nfct_attr_is_set(ct, ATTR_TIMESTAMP_STOP) != -1) {
	} else if (nfct_attr_is_set(ct, ATTR_TIMESTAMP_STOP) != -1) {
	} else {
		/* get timestamp ASAP; conntrack does not supply this, so we are on our own */
		gettimeofday(&tv, NULL);
	}
#else
	gettimeofday(&tv, NULL);
#endif

	/* logs rotation */
	if (rotation_interval && (tv.tv_sec > last_rotation_time) && (tv.tv_sec / rotation_interval != last_rotation_time / rotation_interval))
		new_file(&tv);

	/* buffer */
	struct common *e = &buffer[buffer_pos++];

	/* init */
	e->type = nftype_map[type];
	e->time.sec = htonl(tv.tv_sec);
	e->time.usec = htonl(tv.tv_usec);
	e->addr.orig.src.ip = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
	e->addr.orig.dst.ip = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);
	e->addr.repl.src.ip = nfct_get_attr_u32(ct, ATTR_REPL_IPV4_SRC);
	e->addr.repl.dst.ip = nfct_get_attr_u32(ct, ATTR_REPL_IPV4_DST);

	e->addr.orig.src.port = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC);
	e->addr.orig.dst.port = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST);
	e->addr.repl.src.port = nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC);
	e->addr.repl.dst.port = nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST);

	int status = nfct_get_attr_u32(ct, ATTR_STATUS);
	if (IS_FLAG_SET(status, IPS_SEEN_REPLY))
		e->type |= FLAG_REPLIED;

	stats.saved++;

	if (buffer_pos >= buffer_size)
		buffer_flush();

#if 0
	int res;
	if ((res = safe_write(fd, &e, sizeof(e))) == -1) {
		log_action(LOG_ERR, "write: %s", strerror(errno));
		stats.write_errors++;
	} else {
		stats.written++;
	}
#endif

	return NFCT_CB_CONTINUE;
}


void collect_events()
{
	int res;

	if (!(cth = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_NEW | NF_NETLINK_CONNTRACK_DESTROY))) {
		log_action(LOG_ERR, "can't open conntrack: %s", strerror(errno));
		cleanup();
		exit(1);
	}

	setup_signals(&signal_handler, ARRAY(int, SIGINT, SIGQUIT, SIGTERM, SIGHUP, SIGUSR1, SIGUSR2, 0), ARRAY(int, 0));
	daemonize("ctrecorder", LOG_DAEMON, priority, NULL, pid_file, user, group, 0);

	log_action(LOG_INFO, "%s %s, compiled %s %s, format %08x", PACKAGE, VERSION, __DATE__, __TIME__, CTEVENTLOG_VERSION);
	stats.started = time(NULL);
	if ((buffer = malloc(buffer_size * sizeof(*buffer))) == NULL) {
		log_action(LOG_ERR, "malloc(): %s", strerror(errno));
		cleanup();
		exit(1);
	} else {
		log_action(LOG_DEBUG, "internal buffer size set to %d entries, %d bytes", buffer_size, buffer_size * sizeof(*buffer));
	}

	if (nfnl_buffer_size) {
		res = nfnl_rcvbufsiz(nfct_nfnlh(cth), nfnl_buffer_size);
		log_action(LOG_INFO, "netlink buffer size set to %d bytes", res);
	}

	/* attach filter on L4PROTO */
	log_action(LOG_INFO, "capturing events for protocol %d (%s)", protocol, protoname(protocol));
	/* ... */

	if ((res = nfct_callback_register(cth, NFCT_T_ALL, event, NULL)) != 0) {
		log_action(LOG_ERR, "nfct_callback_register: %d", res);
		cleanup();
		exit(1);
	}

	new_file(NULL);
	for (;;) {
		res = nfct_catch(cth);
		if (res != -1)
			break;

		int _err = errno;
		log_action(LOG_ERR, "nfct_catch(): %d,%s", res, strerror(_err));
		if (_err != ENOBUFS)
			break;

		stats.catch++;
		log_action(LOG_WARNING, "restarting nfct_catch()");
		// write(fd, common.hdr:=LOOSING_EVENTS);
	}

	log_action(LOG_INFO, "done");
	cleanup();
	log_stats();
}
#endif /* DISABLE_CAPTURE */

/* cache */
inline hash common_hash(struct orig_repl a)
{
	hash ret = 0;

	ret ^= a.orig.src.ip;
	ret ^= a.orig.dst.ip;
	ret ^= a.repl.src.ip;
	ret ^= a.repl.dst.ip;

	ret ^= a.orig.src.port;
	ret ^= a.orig.dst.port;
	ret ^= a.repl.src.port;
	ret ^= a.repl.dst.port;

	return ((ret >> 16) ^ ret) % HASH_SIZE;
}

inline void cache_put(struct common_list **cache, struct common entry)
{
	struct common_list *c;
	hash h = common_hash(entry.addr);

	struct common_list *n = malloc(sizeof(*n));
	n->entry = entry;
	n->next = NULL;

	if (!cache[h]) {
		cache[h] = n;
		return;
	}

	for (c = cache[h]; c->next; c = c->next);
	c->next = n;
}

inline struct common *cache_get(struct common_list **cache, struct common entry)
{
	inline int match(struct common e1, struct common e2)
	{
		return 0 == memcmp(&e1.addr, &e2.addr, sizeof(e1.addr));
	}

	static struct common ret;
	hash h = common_hash(entry.addr);

	struct common_list *c, *l;
	for (c = cache[h], l = NULL; c; l = c, c = c->next) {
		if (!match(c->entry, entry))
			continue;

		if (l) {
			l->next = c->next;
		} else {
			cache[h] = c->next;
		}
		ret = c->entry;
		free(c);
		return &ret;
	}

	return NULL;
}

void print_header(FILE* out, struct file_header* fh)
{
	fprintf(out, ".magic: 0x%08x\n", ntohl(fh->magic));
	fprintf(out, ".version: 0x%08x\n", ntohl(fh->version));
	fprintf(out, ".flags: 0x%08x\n", ntohl(fh->flags));
	fprintf(out, ".proto: 0x%02x (%s)\n", fh->proto, protoname(fh->proto));
	fprintf(out, ".hostname: %s\n", fh->hostname);
	fprintf(out, ".start: %s.%06u\n", ltime(ntohl(fh->start_time.sec)), ntohl(fh->start_time.usec));
	#define sd fh->start_time_dec
	fprintf(out, ".startd: %04u.%02u.%02u %02u:%02u:%02u\n", 1900+ntohs(sd.year), sd.month, sd.day, sd.hour, sd.min, sd.sec);
	#undef sd
	fprintf(out, ".end: %s.%06u\n", ltime(ntohl(fh->end_time.sec)), ntohl(fh->end_time.usec));
	fprintf(out, ".tz: %x.%u\n", ntohl(fh->start_tz.minuteswest), ntohl(fh->start_tz.dsttime));
	fprintf(out, ".utc_offset: %d\n", ntohl(fh->utc_offset));
}

void show_header(char *fn)
{
	FILE *file;
	struct file_header fh;

	if (!(file = fopen(fn, "r")))
		die(1, "fopen: %m");

	if (fread(&fh, sizeof(fh), 1, file) != 1)
		die(1, "fread: %m");

	fclose(file);

	TERMINATE_STRING(fh.hostname);
	print_header(stdout, &fh);
}

/* reading events */
void read_events(char* fn, u_int32_t net, u_int32_t mask, u_int16_t port, time_t at_date)
{
	struct common_list **cache = NULL;
	FILE *file;

	net = net & mask;
	inline int ipmatch(struct orig_repl a)
	{
		inline int match(u_int32_t ip)
		{
			return net == (ip & mask);
		}

		return match(a.orig.src.ip) || match(a.orig.dst.ip) || match(a.repl.src.ip) || match(a.repl.dst.ip);
	}

	u_int16_t _port = htons(port);
	inline int portmatch(struct orig_repl a)
	{
		return (_port == a.orig.src.port) || (_port == a.orig.dst.port) || (_port == a.repl.src.port) || (_port == a.repl.dst.port);
	}

	void show_common()
	{
		struct common buf[65536];
		int n, i;
		for (;;) {
			if ((n = fread(&buf, sizeof(struct common), sizeof(buf)/sizeof(struct common), file)) <= 0)
				break;

			for (i=0; i<n; i++) {
				if (mask && !ipmatch(buf[i].addr))
					continue;

				if (_port && !portmatch(buf[i].addr))
					continue;

				if (!cache) {
					show_event_common(buf[i]);
					continue;
				}

				struct common *start;
				struct combined c;

				switch (buf[i].type & NF_BITMASK) {
				case NF_NEW:
					cache_put(cache, buf[i]);
					break;
				case NF_DESTROY:
					start = cache_get(cache, buf[i]);
					c.create.sec = (start) ? start->time.sec : 0;
					c.create.usec = (start) ? start->time.usec : 0;
					c.destroy = buf[i].time;
					c.addr = buf[i].addr;
					show_event_combined(c);
					break;
				}
			}
		}

		/* flush cache */
		if (cache) {
			struct combined c;
			c.destroy.sec = c.destroy.usec = 0;

			for (i=0; i<HASH_SIZE; i++) {
#warning BUG HERE: coredumps, why?
				if (!cache[i])
					continue;

				struct common_list *p;
				for (p = cache[i]; p->next; p = p->next) {
					c.create = p->entry.time;
					c.addr = p->entry.addr;
					show_event_combined(c);
				}
			}
		}
	}

	void show_combined()
	{
		struct combined buf[65536];
		int n, i;

		for (;;) {
			if ((n = fread(&buf, sizeof(struct combined), sizeof(buf)/sizeof(struct combined), file)) <= 0)
				break;

			for (i=0; i<n; i++) {
				if (mask && !ipmatch(buf[i].addr))
					continue;

				if (_port && !portmatch(buf[i].addr))
					continue;

				show_event_combined(buf[i]);
			}
		}
	}

	if (!(file = fopen(fn, "r")))
		die(1, "fopen: %m");

	struct file_header fh;
	if (fread(&fh, sizeof(fh), 1, file) != 1)
		die(1, "fread: %m");

	TERMINATE_STRING(fh.hostname);

	if (!hide_header)
		print_header(stderr, &fh);

	if (fh.magic != htonl(CTEVENTLOG_MAGIC))
		die(1, "Invalid fh.magic");
	if (fh.version != htonl(CTEVENTLOG_VERSION))
		die(1, "Invalid fh.version");
	if (fh.fhlen != htons(sizeof(fh)))
		die(1, "Invalid fh.fhlen");
	if (fh.entrylen != htons(sizeof(struct common)))
		die(1, "Invalid fh.commonlen");
	if ((fh.flags & !htons(GLOBAL_COMBINED)) != htons(0x00))
		die(1, "Invalid fh.flags");

	if (auto_squeeze) {
		if ((cache = calloc(HASH_SIZE, sizeof(*cache))) == NULL)
			die(1, "calloc(cache): %m");
	}

	if (fh.flags == htons(GLOBAL_COMBINED))
		show_combined();
	else
		show_common();

	if (ferror(file))
		fprintf(stderr, "read error: %d\n", ferror(file));

	fclose(file);
}

// output == NULL => squeeze "in place"
void squeeze(char* input, char* output)
{
	// renice() on auto-squeeze
	// save when create+destroy is completed; then flush all create-only and destroy-only
	// should be sorted properly?

	struct common_list **cache = NULL;
	struct common buf[65536];
	struct file_header fh;
	FILE *file, *out;
	int n, i;


	if ((cache = calloc(HASH_SIZE, sizeof(*cache))) == NULL)
		die(1, "calloc(cache): %m");

	if (!(file = fopen(input, "r")))
		die(1, "fopen(input): %m");

	if (fread(&fh, sizeof(fh), 1, file) != 1)
		die(1, "fread(input): %m");

	if (fh.magic != htonl(CTEVENTLOG_MAGIC))
		die(1, "Invalid fh.magic");
	if (fh.version != htonl(CTEVENTLOG_VERSION))
		die(1, "Invalid fh.version");
	if (fh.fhlen != htons(sizeof(fh)))
		die(1, "Invalid fh.fhlen");
	if (fh.entrylen != htons(sizeof(struct common)))
		die(1, "Invalid fh.commonlen");
	if ((fh.flags & !htons(GLOBAL_COMBINED)) != htons(0x00))
		die(1, "Invalid fh.flags");

	if (fh.flags == htons(GLOBAL_COMBINED)) {
		fprintf(stderr, "file already has combined format\n");
		fclose(file);
		exit(0);
	}

	/* open output file and put the same header with flag changed */
	if (!(out = fopen(output, "w")))
		die(1, "fopen(output): %m");

	fh.flags = htons(GLOBAL_COMBINED);
	if (fwrite(&fh, sizeof(fh), 1, out) != 1)
		die(1, "fwrite(output): %m");

	struct combined c;
	memset(&c, '\0', sizeof(c));

	for (;;) {
		if ((n = fread(&buf, sizeof(struct common), sizeof(buf)/sizeof(struct common), file)) <= 0)
			break;

		for (i=0; i<n; i++) {
			struct common *start;

			switch (buf[i].type & NF_BITMASK) {
			case NF_NEW:
				cache_put(cache, buf[i]);
				break;
			case NF_DESTROY:
				start = cache_get(cache, buf[i]);
				c.create.sec = (start) ? start->time.sec : 0;
				c.create.usec = (start) ? start->time.usec : 0;
				c.destroy = buf[i].time;
				c.addr = buf[i].addr;
				if (fwrite(&c, sizeof(c), 1, out) != 1)
					die(1, "fwrite(output): %m");
				break;
			}
		}
	}

	/* flush cache */
	c.destroy.sec = c.destroy.usec = 0;

	for (i=0; i<HASH_SIZE; i++) {
#warning BUG HERE: coredumps, why?
		if (!cache[i])
			continue;

		struct common_list *p;
		for (p = cache[i]; p->next; p = p->next) {
			c.create = p->entry.time;
			c.addr = p->entry.addr;
			if (fwrite(&c, sizeof(c), 1, out) != 1)
				die(1, "fwrite(output): %m");
		}
	}

	if (ferror(file))
		fprintf(stderr, "ferror(input): %d\n", ferror(file));

	if (ferror(out))
		fprintf(stderr, "ferror(output): %d\n", ferror(file));

	fclose(file);
	fclose(out);
}

void test_file(char *fn)
{
	fprintf(stderr, "TODO\n");
	exit(1);
}

void version() __attribute__ ((noreturn));
void version()
{
	printf("%s %s, compiled %s %s\n", PACKAGE, VERSION, __DATE__, __TIME__);
	printf("log format 0x%08x\n", CTEVENTLOG_VERSION);
	printf("struct file_header size: %d\n", sizeof(struct file_header));
	printf("struct common size: %d\n", sizeof(struct common));
	printf("struct combined size: %d\n", sizeof(struct combined));
#ifdef DISABLE_CAPTURE
	printf("Capture mode support: disabled at compilation time!\n");
#else
	printf("Capture mode support: yes\n");
#endif
#ifdef HAVE_DECL_ATTR_TIMESTAMP_START
	printf("Timestamping support: yes\n");
#else
	printf("Timestamping support: not found in netfilter-conntrack\n");
#endif

	exit(0);
}

void usage(int code) __attribute__((noreturn));
void usage(int code)
{
	printf("Usage: ctrecorder [ -C | -L | -T | -S | -H | -h | -V ] options ...\n");
	printf("capture mode: ctrecorder -C ...");
#ifdef DISABLE_CAPTURE
	printf(" (disabled at compilation time)");
#endif
	printf("\n");
	printf("  -f path          output filename, conforming to strftime format, ex. /tmp/ct-%%Y%%m%%d-%%H%%M%%S.log\n");
	printf("  -t minutes       output name change interval\n");
	printf("  -p name          record for protocol: tcp, udp (default: TCP)\n");
//	printf("  -s               auto-squeeze finished files\n");
	printf("  -b kbytes        netlink buffer size\n");
	printf("  -B entries       internal buffer size\n");
	printf("  -N nice          priority\n");
	printf("  -U name          run as user\n");
	printf("  -G name          run as group\n");
	printf("  -P path          pid file\n");
	printf("  -F               run foreground\n");
	printf("list mode: ctrecorder -L -f path [ -i IP/MASK ] [ -p PORT ]\n");
	printf("  -f path          input filename\n");
	printf("  -i IP/mask       list only matching this network\n");
	printf("  -p port          list only matching this port\n");
//	printf("  -a date          active at certain time (YYYY-MM-DD HH:MM:SS)\n");
	printf("  -s               squeeze output\n");
	printf("  -H               hide header\n");
	printf("show header only: ctrecorder -H -f path\n");
	printf("  no optional arguments\n");
	printf("test mode: ctrecorder -T -f path\n");
	printf("  -f path          input filename\n");
	printf("squeeze mode: ctrecorder -S -f path [ -o path ]\n");
	printf("  -f path          input filename\n");
	printf("  -o path          output filename\n");

	exit(code);

/*
	TODO: getopt_long --src --pre-src --post-src ...
	--src IP
	--pre-src IP
	--post-src IP
	--dst IP
	--pre-dst IP
	--post-dst IP

	--sport PORT
	--pre-sport PORT
	--post-sport PORT
	--dport PORT
	--pre-dport PORT
	--post-dport PORT

	--start	TIME
	--end TIME
	--at TIME

	filter grammar: [pre|post] [src|dst] {ip IP | port PORT} | before TIME | after TIME | at TIME | between A B
	
*/
}

void sanity_check()
{
	size_t s = sizeof(struct file_header);

	if (s != HEADER_SIZE) {
		fprintf(stderr, "BUG: sizeof(file_header)=%d != %d\n", s, HEADER_SIZE);
		exit(100);
	}

#if 0
	struct tm tmm;
	time_t t;
	int32_t i;

	t = time(NULL);
	localtime_r(&t, &tmm);
	i = htonl(tmm.tm_gmtoff);
	printf("%ld\n%d\n", t, ntohl(i));
#endif
}

#if 0
typedef enum {
	OPT_START = 130, OPT_END,
	OPT_IP,
	OPT_SRC, OPT_PRE_SRC, OPT_POST_SRC,
	OPT_DST, OPT_PRE_DST, OPT_POST_DST,
	OPT_PORT,
	OPT_SPORT, OPT_PRE_SPORT, OPT_POST_SPORT,
	OPT_DPORT, OPT_PRE_DPORT, OPT_POST_DPORT,
};

typedef enum {
	MATCH_INVALID = 0,
	MATCH_IP,
	MATCH_PORT
} match_type_t;
typedef enum {
	MATCH_ALL = 0,
	MATCH_SRC = 1,
	MATCH_DST = 2,
	MATCH_SRC_DST = 3
} match_direction_t;
typedef enum {
	MATCH_PRE = 1,
	MATCH_POST = 2,
	MATCH_PRE_POST = 3
} match_stage;

typedef filter_t {
	

};
#endif

int main(int argc, char* argv[])
{
	u_int32_t ip = 0, mask = 0;
	u_int16_t port = 0;
	char *ofn = NULL;
	time_t at_date = 0;
	struct tm at_date_tm;
	struct protoent *p;
	enum { M_NONE, M_COLLECT, M_READ, M_TEST, M_SQUEEZE, M_HEADER } mode = M_NONE;
	const char *short_options = "CLSTf:o:i:p:t:b:B:N:U:G:P:a:sFHhV";

#if 0
	int option_index = 0;
	const struct option long_options[] = {
		{ "start", required_argument, 0, OPT_START },
		{ "end", required_argument, 0, OPT_END },
		{ "at", required_argument, 0, OPT_AT },
		{ "ip", required_argument, 0, OPT_IP },
		{ "src", required_argument, 0, OPT_SRC },
		{ "pre-src", required_argument, 0, OPT_PRE_SRC },
		{ "post-src", required_argument, 0, OPT_POST_SRC },
		{ "dst", required_argument, 0, OPT_DST },
		{ "pre-dst", required_argument, 0, OPT_PRE_DST },
		{ "post-dst", required_argument, 0, OPT_POST_DST },
		{ "port", required_argument, 0, OPT_PORT },
		{ "sport", required_argument, 0, OPT_SPORT },
		{ "pre-sport", required_argument, 0, OPT_PRE_SPORT },
		{ "post-sport", required_argument, 0, OPT_POST_SPORT },
		{ "dport", required_argument, 0, OPT_DPORT },
		{ "pre-dport", required_argument, 0, OPT_PRE_DPORT },
		{ "post-dport", required_argument, 0, OPT_POST_DPORT },
		{ NULL, 0, NULL, 0 }
	};
#endif

	sanity_check();
	tzset();

	char opt;
	while ((opt = getopt(argc, argv, short_options)) != -1) {
		if (mode == M_NONE)
			switch (opt) {
			case 'C':
				mode = M_COLLECT;
				break;
			case 'L':
				mode = M_READ;
				break;
			case 'T':
				mode = M_TEST;
				break;
			case 'S':
				mode = M_SQUEEZE;
				break;
			case 'H':
				mode = M_HEADER;
				break;
			case 'h':
				usage(0);
			case 'V':
				version(0);
			case '?':
				usage(1);
			}

		if (mode == M_NONE)
			die(1, "Please define mode as first argument");

		switch (opt) {
		case 'f':
			fnt = optarg;
			break;
		case 'o':
			ofn = optarg;
			break;
		case 'F':
			foreground = 1;
			break;
		case 's':
			auto_squeeze = 1;
			break;
		case 'H':
			hide_header = 1;
			break;
		case 'i':
			if (parse_ip_mask(optarg, &ip, &mask) == -1)
				die(1, "Invalid ip: %s", optarg);
			break;
		case 'p':
			switch (mode) {
				case M_COLLECT:
					if ((p = getprotobyname(optarg)) == NULL)
						die(1, "Unknown protocol %s", optarg);
					protocol = p->p_proto;
					break;
				case M_READ:
					port = atoi(optarg);
					break;
				default:
					break;
			}
			break;
		case 't':
			rotation_interval = atoi(optarg) * 60;
			break;
		case 'N':
			priority = atoi(optarg);
			break;
		case 'U':
			user = optarg;
			break;
		case 'G':
			group = optarg;
			break;
		case 'P':
			pid_file = optarg;
			break;
		case 'b':
			nfnl_buffer_size = atoi(optarg) * 1024;
			break;
		case 'a':
			if (strptime(optarg, "", &at_date_tm) == NULL)
				die(1, "Unknown date format");
			at_date = mktime(&at_date_tm);
			break;
		case 'B':
			buffer_size = atoi(optarg);
			break;
		}
	}

	if (!fnt)
		usage(1);

	memset(&stats, 0, sizeof(stats));
	switch (mode) {
		case M_COLLECT:
#ifndef DISABLE_CAPTURE
			collect_events();
#else
			fprintf(stderr, "Capture mode disabled at compilation time\n");
#endif
			break;
		case M_READ:
			foreground = 1;
			read_events(fnt, ip, mask, port, at_date);
			break;
		case M_HEADER:
			foreground = 1;
			show_header(fnt);
			break;
		case M_TEST:
			foreground = 1;
			test_file(fnt);
			break;
		case M_SQUEEZE:
			foreground = 1;
			squeeze(fnt, ofn);
			break;
		default:
			usage(1);
	}
	return 0;
}


