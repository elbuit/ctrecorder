#ifndef DISABLE_CAPTURE
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#else
#define NF_NETLINK_CONNTRACK_NEW                0x00000001
#define NF_NETLINK_CONNTRACK_UPDATE             0x00000002
#define NF_NETLINK_CONNTRACK_DESTROY            0x00000004
#endif

// "CTEL": conntrack event log
#define CTEVENTLOG_MAGIC	0x43544e4c
// file format version
#define CTEVENTLOG_VERSION	0x00000002
#define HEADER_SIZE		256


typedef unsigned long long llu;
typedef u_int32_t hash;


/* structures */
struct my_time {
	u_int32_t sec, usec;
} __attribute__ ((packed));

struct my_timezone {
	u_int32_t minuteswest, dsttime;
	// maybe tzset() => daylight, timezone; does this change during CET/CEST change or is it static?
} __attribute__ ((packed));

struct my_time_dec {
	u_int16_t year;
	u_int8_t month, day, hour, min, sec;
} __attribute__ ((packed));


/* all fields are network byte ordered */
struct file_header {
	u_int32_t magic;	
	u_int32_t version;
	u_int16_t fhlen;	// sizeof(file_header)
	u_int16_t entrylen;	// sizeof(common)
	u_int16_t fflen;	// sizeof(file_footer)
	u_int32_t flags;	// GLOBAL_*
	u_int8_t proto;		// TCP, UDP, SCTP?
	char hostname[33];
	struct my_time start_time;
	struct my_time end_time;	// to be filled on rotation
	struct my_timezone start_tz;
	int32_t utc_offset;
	// 20110609 "decimal" start localtime
	struct my_time_dec start_time_dec;
	/* new fields must be added before "unused" to retain backward compatibility */
	u_int8_t unused[169];
} __attribute__ ((packed));

enum {
	/* conntrack actions; enum */
	NF_RESERVED		= 0x00,
	NF_NEW			= 0x01,		// NFCT_MSG_NEW,
	NF_UPDATE		= 0x02,		// NFCT_MSG_UPDATE,
	NF_DESTROY		= 0x03,		// NFCT_MSG_DESTROY,
	NF_BITMASK		= (NF_RESERVED | NF_NEW | NF_UPDATE | NF_DESTROY),
	/* flags */
	FLAG_REPLIED		= 0x04,
	FLAG_BITMASK		= (FLAG_REPLIED),
};

enum {
	// events are stored as struct combined
	GLOBAL_COMBINED		= 0x01,
	// foreach n: time[n] <= time[n+1], header updated after log finished
	// allows sorted seek
	GLOBAL_TIME_LINEAR	= 0x02,
};

struct ip_port {
	u_int32_t ip;
	u_int16_t port;
} __attribute__ ((packed));

struct src_dst {
	struct ip_port src, dst;
} __attribute__ ((packed));

struct orig_repl {
	struct src_dst orig, repl;
} __attribute__ ((packed));

/* common format */
struct common {
	u_int8_t type;		// MSG_NEW, MSG_DESTROY
	struct my_time time;	// [sec] part
	struct orig_repl addr;
} __attribute__ ((packed));

struct common_list {
	u_int8_t type;
	struct common entry;
	struct common_list *next;
};

/* combined format */
struct combined {
	struct my_time create, destroy;
	struct orig_repl addr;
} __attribute__ ((packed));


