// IP protocols
#if 0
protocol_list = {
	'tcp',
	'udp',
	'icmp',
	'sctp',
	NULL
};

// conntrack events
event_list = {
	'new',
	'update',
	'destroy',
	NULL
};

tcp_states_list = {
	"syn-sent",
	"syn-rcvd",
	"established",
	"fin-wait",
	"close-wait",
	"last-ack",
	"time-wait",
	"close",
	"listen",
	NULL
};
#endif

#if 0
CONF_OPT_ENUM(tcp_states, ALLOW_MULTI, tcp_state_list)
CONF_OPT_ENUM(protocols, ALLOW_MULTI|ALLOW_INTEGER, protocol_list)
CONF_OPT_ENUM(events, ALLOW_MULTI, event_list

CONF_OPT_STRING(log_path, "/var/log/ulog")
CONF_OPT_STRING(log_file, "%Y%m%d-%h%m%s.ct")

#endif


