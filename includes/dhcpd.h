/* dhcpd.h

   Definitions for dhcpd... */

/*
 * Copyright (c) 1996-1999 Internet Software Consortium.
 * Use is subject to license terms which appear in the file named
 * ISC-LICENSE that should have accompanied this file when you
 * received it.   If a file named ISC-LICENSE did not accompany this
 * file, or you are not sure the one you have is correct, you may
 * obtain an applicable copy of the license at:
 *
 *             http://www.isc.org/isc-license-1.0.html. 
 *
 * This file is part of the ISC DHCP distribution.   The documentation
 * associated with this file is listed in the file DOCUMENTATION,
 * included in the top-level directory of this release.
 *
 * Support and other services are available for ISC products - see
 * http://www.isc.org for more information.
 */

#ifndef __CYGWIN32__
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

#if defined (NSUPDATE)
# include <arpa/nameser.h>
# include <resolv.h>
# include <res_update.h>
#endif

#include <netdb.h>
#else
#define fd_set cygwin_fd_set
#include <sys/types.h>
#endif
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <ctype.h>
#include <time.h>

#include "cdefs.h"
#include "osdep.h"
#include "dhcp.h"
#include "statement.h"
#include "tree.h"
#include "hash.h"
#include "inet.h"
#include "auth.h"

#if !defined (OPTION_HASH_SIZE)
# define OPTION_HASH_SIZE 17
#endif

/* Variable-length array of data. */

struct string_list {
	struct string_list *next;
	char string [1];
};

/* A name server, from /etc/resolv.conf. */
struct name_server {
	struct name_server *next;
	struct sockaddr_in addr;
	TIME rcdate;
};

/* A domain search list element. */
struct domain_search_list {
	struct domain_search_list *next;
	char *domain;
	TIME rcdate;
};

/* Option tag structures are used to build chains of option tags, for
   when we're sure we're not going to have enough of them to justify
   maintaining an array. */

struct option_tag {
	struct option_tag *next;
	u_int8_t data [1];
};

/* An agent option structure.   We need a special structure for the
   Relay Agent Information option because if more than one appears in
   a message, we have to keep them seperate. */

struct agent_options {
	struct agent_options *next;
	int length;
	struct option_tag *first;
};

struct option_cache {
	int refcnt;
	struct option_cache *next;
	struct expression *expression;
	struct option *option;
	struct data_string data;
};

struct option_state {
	int refcnt;
	int universe_count;
	int site_universe;
	int site_code_min;
	VOIDPTR universes [1];
};

/* A dhcp packet and the pointers to its option values. */
struct packet {
	struct dhcp_packet *raw;
	int packet_length;
	int packet_type;
	int options_valid;
	int client_port;
	struct iaddr client_addr;
	struct interface_info *interface;	/* Interface on which packet
						   was received. */
	struct hardware *haddr;		/* Physical link address
					   of local sender (maybe gateway). */

	/* Information for relay agent options (see
	   draft-ietf-dhc-agent-options-xx.txt). */
	u_int8_t *circuit_id;		/* Circuit ID of client connection. */
	int circuit_id_len;
	u_int8_t *remote_id;		/* Remote ID of client. */
	int remote_id_len;

	int got_requested_address;	/* True if client sent the
					   dhcp-requested-address option. */

	struct shared_network *shared_network;
	struct option_state *options;

#if !defined (PACKET_MAX_CLASSES)
# define PACKET_MAX_CLASSES 5
#endif
	int class_count;
	struct class *classes [PACKET_MAX_CLASSES];

	int known;
	int authenticated;
};

/* A network interface's MAC address. */

struct hardware {
	u_int8_t htype;
	u_int8_t hlen;
	u_int8_t haddr [16];
};

/* A dhcp lease declaration structure. */
struct lease {
	struct lease *next;
	struct lease *prev;
	struct lease *n_uid, *n_hw;
	struct lease *waitq_next;

#if defined (FAILOVER)
	TIME tstp;	/* Time sent to partner. */
	TIME trfp;	/* Time sent from partner. */
#endif
	struct iaddr ip_addr;
	TIME starts, ends, timestamp;
	unsigned char *uid;
	int uid_len;
	int uid_max;
	unsigned char uid_buf [32];
	char *hostname;
	char *client_hostname;
	char *ddns_fwd_name;
	char *ddns_rev_name;
	struct host_decl *host;
	struct subnet *subnet;
	struct pool *pool;
	struct class *billing_class;
	struct hardware hardware_addr;

	int flags;
#       define STATIC_LEASE		1
#       define BOOTP_LEASE		2
#	define PERSISTENT_FLAGS		(0)
#	define MS_NULL_TERMINATION	8
#	define ABANDONED_LEASE		16
#	define EPHEMERAL_FLAGS		(BOOTP_LEASE | MS_NULL_TERMINATION | \
					 ABANDONED_LEASE)

	struct lease_state *state;
};

struct lease_state {
	struct lease_state *next;

	struct interface_info *ip;

	TIME offered_expiry;

	struct option_state *options;
	struct data_string parameter_request_list;
	int max_message_size;
	u_int32_t expiry, renewal, rebind;
	struct data_string filename, server_name;
	int got_requested_address;
	int got_server_identifier;
	struct shared_network *shared_network;	/* Shared network of interface
						   on which request arrived. */

	u_int32_t xid;
	u_int16_t secs;
	u_int16_t bootp_flags;
	struct in_addr ciaddr;
	struct in_addr siaddr;
	struct in_addr giaddr;
	u_int8_t hops;
	u_int8_t offer;
	struct iaddr from;
};

#define	ROOT_GROUP	0
#define HOST_DECL	1
#define SHARED_NET_DECL	2
#define SUBNET_DECL	3
#define CLASS_DECL	4
#define	GROUP_DECL	5
#define POOL_DECL	6

/* Possible modes in which discover_interfaces can run. */

#define DISCOVER_RUNNING	0
#define DISCOVER_SERVER		1
#define DISCOVER_UNCONFIGURED	2
#define DISCOVER_RELAY		3
#define DISCOVER_REQUESTED	4

/* Server option names. */

#define SV_DEFAULT_LEASE_TIME		1
#define SV_MAX_LEASE_TIME		2
#define SV_MIN_LEASE_TIME		3
#define SV_BOOTP_LEASE_CUTOFF		4
#define SV_BOOTP_LEASE_LENGTH		5
#define SV_BOOT_UNKNOWN_CLIENTS		6
#define SV_DYNAMIC_BOOTP		7
#define	SV_ALLOW_BOOTP			8
#define	SV_ALLOW_BOOTING		9
#define	SV_ONE_LEASE_PER_CLIENT		10
#define	SV_GET_LEASE_HOSTNAMES		11
#define	SV_USE_HOST_DECL_NAMES		12
#define	SV_USE_LEASE_ADDR_FOR_DEFAULT_ROUTE	13
#define	SV_MIN_SECS			14
#define	SV_FILENAME			15
#define SV_SERVER_NAME			16
#define	SV_NEXT_SERVER			17
#define SV_AUTHORITATIVE		18
#define SV_VENDOR_OPTION_SPACE		19
#define SV_ALWAYS_REPLY_RFC1048		20
#define SV_SITE_OPTION_SPACE		21
#define SV_ALWAYS_BROADCAST		22
#define SV_DDNS_DOMAIN_NAME		23
#define SV_DDNS_HOST_NAME		24
#define SV_DDNS_REV_DOMAIN_NAME		25

#if !defined (DEFAULT_DEFAULT_LEASE_TIME)
# define DEFAULT_DEFAULT_LEASE_TIME 43200
#endif

#if !defined (DEFAULT_MIN_LEASE_TIME)
# define DEFAULT_MIN_LEASE_TIME 0
#endif

#if !defined (DEFAULT_MAX_LEASE_TIME)
# define DEFAULT_MAX_LEASE_TIME 86400
#endif

/* Client option names */

#define	CL_TIMEOUT		1
#define	CL_SELECT_INTERVAL	2
#define CL_REBOOT_TIMEOUT	3
#define CL_RETRY_INTERVAL	4
#define CL_BACKOFF_CUTOFF	5
#define CL_INITIAL_INTERVAL	6
#define CL_BOOTP_POLICY		7
#define	CL_SCRIPT_NAME		8
#define CL_REQUESTED_OPTIONS	9
#define CL_REQUESTED_LEASE_TIME	10
#define CL_SEND_OPTIONS		11
#define CL_MEDIA		12
#define	CL_REJECT_LIST		13

#ifndef CL_DEFAULT_TIMEOUT
# define CL_DEFAULT_TIMEOUT	60
#endif

#ifndef CL_DEFAULT_SELECT_INTERVAL
# define CL_DEFAULT_SELECT_INTERVAL 0
#endif

#ifndef CL_DEFAULT_REBOOT_TIMEOUT
# define CL_DEFAULT_REBOOT_TIMEOUT 10
#endif

#ifndef CL_DEFAULT_RETRY_INTERVAL
# define CL_DEFAULT_RETRY_INTERVAL 300
#endif

#ifndef CL_DEFAULT_BACKOFF_CUTOFF
# define CL_DEFAULT_BACKOFF_CUTOFF 120
#endif

#ifndef CL_DEFAULT_INITIAL_INTERVAL
# define CL_DEFAULT_INITIAL_INTERVAL 10
#endif

#ifndef CL_DEFAULT_BOOTP_POLICY
# define CL_DEFAULT_BOOTP_POLICY P_ACCEPT
#endif

#ifndef CL_DEFAULT_SCRIPT_NAME
# define CL_DEFAULT_SCRIPT_NAME "/etc/dhclient-script"
#endif

#ifndef CL_DEFAULT_REQUESTED_OPTIONS
# define CL_DEFAULT_REQUESTED_OPTIONS \
	{ DHO_SUBNET_MASK, \
	  DHO_BROADCAST_ADDRESS, \
	  DHO_TIME_OFFSET, \
	  DHO_ROUTERS, \
	  DHO_DOMAIN_NAME, \
	  DHO_DOMAIN_NAME_SERVERS, \
	  DHO_HOST_NAME }
#endif

/* Group of declarations that share common parameters. */
struct group {
	struct group *next;

	struct subnet *subnet;
	struct shared_network *shared_network;
	int authoritative;
	struct executable_statement *statements;
};

/* A dhcp host declaration structure. */
struct host_decl {
	struct host_decl *n_ipaddr;
	char *name;
	struct hardware interface;
	struct data_string client_identifier;
	struct option_cache *fixed_addr;
	struct group *group;
	struct data_string auth_key_id;
};

struct permit {
	struct permit *next;
	enum {
		permit_unknown_clients,
		permit_known_clients,
		permit_authenticated_clients,
		permit_unauthenticated_clients,
		permit_all_clients,
		permit_dynamic_bootp_clients,
		permit_class,
	} type;
	struct class *class;
};

struct pool {
	struct pool *next;
	struct group *group;
	struct shared_network *shared_network;
	struct permit *permit_list;
	struct permit *prohibit_list;
	struct lease *leases;
	struct lease *insertion_point;
	struct lease *last_lease;
	struct lease *next_expiry;
};

/* A failover peer. */
enum failover_state {
	invalid_state,
	partner_down,
	normal,
	communications_interrupted,
	potential_conflict,
	recover
};

#if defined (FAILOVER_PROTOCOL)
struct failover_peer {
	char *name;			/* Name of this failover instance. */
	struct expression *address;	/* Partner's IP address or hostname. */
	int port;			/* Partner's TCP port. */
	enum failover_state partner_state;
	enum failover_state my_state;
	enum {
		primary, secondary
	} i_am;		/* We are primary or secondary in this relationship. */

	TIME last_packet_sent;		/* Timestamp on last packet we sent. */
	TIME last_timestamp_received;	/* The last timestamp we sent that
					   has been returned by our partner. */
	TIME skew;	/* The skew between our clock and our partner's. */
	TIME max_transmit_idle;	/* Always send a poll if we haven't sent
				   some other packet more recently than
				   this. */
	TIME max_response_delay;	/* If the returned timestamp on the
					   last packet we received is older
					   than this, communications have been
					   interrupted. */
	struct lease *update_queue;	/* List of leases we haven't sent
					   to peer. */
	struct lease *ack_queue;	/* List of lease updates the peer
					   hasn't yet acked. */
	/* XXX Is ack_queue just a pointer to earlier in the same list?
	   XXX Make sure that if we send an update before an ack has
	   XXX been received on a previous update, that we don't either
	   XXX take the previous ack as an ack for the subsequent update
	   XXX or, when putting the lease back on the update list,
	   XXX accidentally set the ack queue pointer forward, which would
	   XXX happen if the ack queue and update queue are the same list
	   XXX and the ack queue pointer is pointing at the lease that
	   XXX gets put back on the update queue. */
};
#endif /* defined (FAILOVER_PROTOCOL) */

struct shared_network {
	struct shared_network *next;
	char *name;
	struct subnet *subnets;
	struct interface_info *interface;
	struct pool *pools;
#if defined (FAILOVER_PROTOCOL)
	struct failover_peer *failover_peer;
#endif
	struct group *group;
};

struct subnet {
	struct subnet *next_subnet;
	struct subnet *next_sibling;
	struct shared_network *shared_network;
	struct interface_info *interface;
	struct iaddr interface_address;
	struct iaddr net;
	struct iaddr netmask;

	struct group *group;
};

struct collection {
	struct collection *next;
	
	char *name;
	struct class *classes;
};

/* XXX classes must be reference-counted. */
struct class {
	struct class *nic;	/* Next in collection. */
	struct class *superclass;	/* Set for spawned classes only. */
	char *name;		/* Not set for spawned classes. */

	/* A class may be configured to permit a limited number of leases. */
	int lease_limit;
	int leases_consumed;
	struct lease **billed_leases;

	/* If nonzero, class has not been saved since it was last
	   modified. */
	int dirty;

	/* Hash table containing subclasses. */
	struct hash_table *hash;
	struct data_string hash_string;

	/* Expression used to match class. */
	struct expression *expr;

	/* Expression used to compute subclass identifiers for spawning
	   and to do subclass matching. */
	struct expression *submatch;
	int spawning;
	
	struct group *group;

	/* Statements to execute if class matches. */
	struct executable_statement *statements;
};

/* DHCP client lease structure... */
struct client_lease {
	struct client_lease *next;		      /* Next lease in list. */
	TIME expiry, renewal, rebind;			  /* Lease timeouts. */
	struct iaddr address;			    /* Address being leased. */
	char *server_name;			     /* Name of boot server. */
	char *filename;		     /* Name of file we're supposed to boot. */
	struct string_list *medium;			  /* Network medium. */
	struct data_string auth_key_id;	      /* Authentication key ID used. */

	unsigned int is_static : 1;    /* If set, lease is from config file. */
	unsigned int is_bootp: 1;   /* If set, lease was aquired with BOOTP. */

	struct option_state *options;	     /* Options supplied with lease. */
};

/* Possible states in which the client can be. */
enum dhcp_state {
	S_REBOOTING,
	S_INIT,
	S_SELECTING,
	S_REQUESTING, 
	S_BOUND,
	S_RENEWING,
	S_REBINDING
};

/* Authentication and BOOTP policy possibilities (not all values work
   for each). */
enum policy { P_IGNORE, P_ACCEPT, P_PREFER, P_REQUIRE, P_DONT };

/* Configuration information from the config file... */
struct client_config {
	/*
	 * When a message has been received, run these statements
	 * over it.
	 */
	struct group *on_receipt;

	/*
	 * When a message is sent, run these statements.
	 */
	struct group *on_transmission;

	u_int32_t *required_options; /* Options server must supply. */
	u_int32_t *requested_options; /* Options to request from server. */

	TIME timeout;			/* Start to panic if we don't get a
					   lease in this time period when
					   SELECTING. */
	TIME initial_interval;		/* All exponential backoff intervals
					   start here. */
	TIME retry_interval;		/* If the protocol failed to produce
					   an address before the timeout,
					   try the protocol again after this
					   many seconds. */
	TIME select_interval;		/* Wait this many seconds from the
					   first DHCPDISCOVER before
					   picking an offered lease. */
	TIME reboot_timeout;		/* When in INIT-REBOOT, wait this
					   long before giving up and going
					   to INIT. */
	TIME backoff_cutoff;		/* When doing exponential backoff,
					   never back off to an interval
					   longer than this amount. */
	u_int32_t requested_lease;	/* Requested lease time, if user
					   doesn't configure one. */
	struct string_list *media;	/* Possible network media values. */
	char *script_name;		/* Name of config script. */
	enum policy bootp_policy;
					/* Ignore, accept or prefer BOOTP
					   responses. */
	enum policy auth_policy;
					/* Require authentication, prefer
					   authentication, or don't try to
					   authenticate. */
	struct string_list *medium;	/* Current network medium. */

	struct iaddrlist *reject_list;	/* Servers to reject. */

	struct option_state *send_options;	/* Options to send. */
};

/* Per-interface state used in the dhcp client... */
struct client_state {
	struct client_state *next;
	struct interface_info *interface;
	char *name;

	struct client_lease *active;		  /* Currently active lease. */
	struct client_lease *new;			       /* New lease. */
	struct client_lease *offered_leases;	    /* Leases offered to us. */
	struct client_lease *leases;		/* Leases we currently hold. */
	struct client_lease *alias;			     /* Alias lease. */

	enum dhcp_state state;		/* Current state for this interface. */
	struct iaddr destination;		    /* Where to send packet. */
	u_int32_t xid;					  /* Transaction ID. */
	u_int16_t secs;			    /* secs value from DHCPDISCOVER. */
	TIME first_sending;			/* When was first copy sent? */
	TIME interval;		      /* What's the current resend interval? */
	struct string_list *medium;		   /* Last media type tried. */
	struct dhcp_packet packet;		    /* Outgoing DHCP packet. */
	int packet_length;	       /* Actual length of generated packet. */

	struct iaddr requested_address;	    /* Address we would like to get. */

	struct client_config *config;		    /* Client configuration. */
};

/* Information about each network interface. */

struct interface_info {
	struct interface_info *next;	/* Next interface in list... */
	struct shared_network *shared_network;
				/* Networks connected to this interface. */
	struct hardware hw_address;	/* Its physical address. */
	struct in_addr primary_address;	/* Primary interface address. */

	u_int8_t *circuit_id;		/* Circuit ID associated with this
					   interface. */
	int circuit_id_len;		/* Length of Circuit ID, if there
					   is one. */
	u_int8_t *remote_id;		/* Remote ID associated with this
					   interface (if any). */
	int remote_id_len;		/* Length of Remote ID. */

	char name [IFNAMSIZ];		/* Its name... */
	int rfdesc;			/* Its read file descriptor. */
	int wfdesc;			/* Its write file descriptor, if
					   different. */
	unsigned char *rbuf;		/* Read buffer, if required. */
	size_t rbuf_max;		/* Size of read buffer. */
	size_t rbuf_offset;		/* Current offset into buffer. */
	size_t rbuf_len;		/* Length of data in buffer. */

	struct ifreq *ifp;		/* Pointer to ifreq struct. */
	u_int32_t flags;		/* Control flags... */
#define INTERFACE_REQUESTED 1
#define INTERFACE_AUTOMATIC 2

	/* Only used by DHCP client code. */
	struct client_state *client;
};

struct hardware_link {
	struct hardware_link *next;
	char name [IFNAMSIZ];
	struct hardware address;
};

struct timeout {
	struct timeout *next;
	TIME when;
	void (*func) PROTO ((void *));
	void *what;
};

struct protocol {
	struct protocol *next;
	int fd;
	void (*handler) PROTO ((struct protocol *));
	void *local;
};

struct dns_query; /* forward */

struct dns_wakeup {
	struct dns_wakeup *next;	/* Next wakeup in chain. */
	void (*func) PROTO ((struct dns_query *));
};

struct dns_question {
	u_int16_t type;			/* Type of query. */
	u_int16_t class;		/* Class of query. */
	unsigned char data [1];		/* Query data. */
};

struct dns_answer {
	u_int16_t type;			/* Type of answer. */
	u_int16_t class;		/* Class of answer. */
	int count;			/* Number of answers. */
	unsigned char *answers[1];	/* Pointers to answers. */
};

struct dns_query {
	struct dns_query *next;		/* Next query in hash bucket. */
	u_int32_t hash;			/* Hash bucket index. */
	TIME expiry;			/* Query expiry time (zero if not yet
					   answered. */
	u_int16_t id;			/* Query ID (also hash table index) */
	caddr_t waiters;		/* Pointer to list of things waiting
					   on this query. */

	struct dns_question *question;	/* Question, internal format. */
	struct dns_answer *answer;	/* Answer, internal format. */

	unsigned char *query;		/* Query formatted for DNS server. */
	int len;			/* Length of entire query. */
	int sent;			/* The query has been sent. */
	struct dns_wakeup *wakeups;	/* Wakeups to call if this query is
					   answered. */
	struct name_server *next_server;	/* Next server to try. */
	int backoff;			/* Current backoff, in seconds. */
};

/* Bitmask of dhcp option codes. */
typedef unsigned char option_mask [16];

/* DHCP Option mask manipulation macros... */
#define OPTION_ZERO(mask)	(memset (mask, 0, 16))
#define OPTION_SET(mask, bit)	(mask [bit >> 8] |= (1 << (bit & 7)))
#define OPTION_CLR(mask, bit)	(mask [bit >> 8] &= ~(1 << (bit & 7)))
#define OPTION_ISSET(mask, bit)	(mask [bit >> 8] & (1 << (bit & 7)))
#define OPTION_ISCLR(mask, bit)	(!OPTION_ISSET (mask, bit))

/* An option occupies its length plus two header bytes (code and
    length) for every 255 bytes that must be stored. */
#define OPTION_SPACE(x)		((x) + 2 * ((x) / 255 + 1))

/* Default path to dhcpd config file. */
#ifdef DEBUG
#undef _PATH_DHCPD_CONF
#define _PATH_DHCPD_CONF	"dhcpd.conf"
#undef _PATH_DHCPD_DB
#define _PATH_DHCPD_DB		"dhcpd.leases"
#else
#ifndef _PATH_DHCPD_CONF
#define _PATH_DHCPD_CONF	"/etc/dhcpd.conf"
#endif

#ifndef _PATH_DHCPD_DB
#define _PATH_DHCPD_DB		"/etc/dhcpd.leases"
#endif

#ifndef _PATH_DHCPD_PID
#define _PATH_DHCPD_PID		"/var/run/dhcpd.pid"
#endif
#endif

#ifndef _PATH_DHCLIENT_CONF
#define _PATH_DHCLIENT_CONF	"/etc/dhclient.conf"
#endif

#ifndef _PATH_DHCLIENT_PID
#define _PATH_DHCLIENT_PID	"/var/run/dhclient.pid"
#endif

#ifndef _PATH_DHCLIENT_DB
#define _PATH_DHCLIENT_DB	"/etc/dhclient.leases"
#endif

#ifndef _PATH_RESOLV_CONF
#define _PATH_RESOLV_CONF	"/etc/resolv.conf"
#endif

#ifndef _PATH_DHCRELAY_PID
#define _PATH_DHCRELAY_PID	"/var/run/dhcrelay.pid"
#endif

#ifndef DHCPD_LOG_FACILITY
#define DHCPD_LOG_FACILITY	LOG_DAEMON
#endif

#define MAX_TIME 0x7fffffff
#define MIN_TIME 0

/* External definitions... */

/* options.c */

int parse_options PROTO ((struct packet *));
int parse_option_buffer PROTO ((struct packet *, unsigned char *, int));
int parse_agent_information_option PROTO ((struct packet *, int, u_int8_t *));
int cons_options PROTO ((struct packet *, struct dhcp_packet *, struct lease *,
			 int, struct option_state *,
			 int, int, int, struct data_string *));
int store_options PROTO ((unsigned char *, int,
			  struct lease *, struct option_state *,
			  int *, int, int, int, int));
char *pretty_print_option PROTO ((unsigned int,
				  unsigned char *, int, int, int));
void do_packet PROTO ((struct interface_info *,
		       struct dhcp_packet *, int,
		       unsigned int, struct iaddr, struct hardware *));
int hashed_option_get PROTO ((struct data_string *, struct universe *,
			      struct packet *, struct lease *,
			      struct option_state *, int));
int agent_option_get PROTO ((struct data_string *, struct universe *,
			      struct packet *, struct lease *,
			     struct option_state *, int));
void hashed_option_set PROTO ((struct universe *, struct option_state *,
			       struct option_cache *,
			       enum statement_op));
struct option_cache *lookup_option PROTO ((struct universe *,
					   struct option_state *, int));
struct option_cache *lookup_hashed_option PROTO ((struct universe *,
						  struct option_state *, int));
void save_option PROTO ((struct universe *,
			 struct option_state *, struct option_cache *));
void save_hashed_option PROTO ((struct universe *,
				struct option_state *, struct option_cache *));
void delete_option PROTO ((struct universe *, struct option_state *, int));
void delete_hashed_option PROTO ((struct universe *,
				  struct option_state *, int));
int option_cache_dereference PROTO ((struct option_cache **, char *));
int hashed_option_state_dereference PROTO ((struct universe *,
					    struct option_state *));
int agent_option_state_dereference PROTO ((struct universe *,
					   struct option_state *));
int store_option PROTO ((struct data_string *,
			 struct universe *, struct lease *,
			 struct option_cache *));
int option_space_encapsulate PROTO ((struct data_string *,
				     struct option_state *,
				     struct lease *,
				     struct data_string *));
int hashed_option_space_encapsulate PROTO ((struct data_string *,
					    struct option_state *,
					    struct lease *,
					    struct universe *));
int agent_option_space_encapsulate PROTO ((struct data_string *,
					   struct option_state *,
					   struct lease *,
					   struct universe *));

/* errwarn.c */
extern int warnings_occurred;
void log_fatal PROTO ((char *, ...))
	__attribute__((__format__(__printf__,1,2)));
int log_error PROTO ((char *, ...))
	__attribute__((__format__(__printf__,1,2)));
int log_info PROTO ((char *, ...))
	__attribute__((__format__(__printf__,1,2)));
int log_debug PROTO ((char *, ...))
	__attribute__((__format__(__printf__,1,2)));
int parse_warn PROTO ((char *, ...))
	__attribute__((__format__(__printf__,1,2)));

/* dhcpd.c */
extern TIME cur_time;
extern struct group root_group;
extern struct in_addr limited_broadcast;

extern u_int16_t local_port;
extern u_int16_t remote_port;
extern int log_priority;
extern int log_perror;

extern char *path_dhcpd_conf;
extern char *path_dhcpd_db;
extern char *path_dhcpd_pid;

extern int dhcp_max_agent_option_packet_length;

int main PROTO ((int, char **, char **));
void cleanup PROTO ((void));
void lease_pinged PROTO ((struct iaddr, u_int8_t *, int));
void lease_ping_timeout PROTO ((void *));

/* conflex.c */
extern int lexline, lexchar;
extern char *token_line, *tlname;
extern char comments [4096];
extern int comment_index;
extern int eol_token;
void new_parse PROTO ((char *));
enum dhcp_token next_token PROTO ((char **, FILE *));
enum dhcp_token peek_token PROTO ((char **, FILE *));

/* confpars.c */
int readconf PROTO ((void));
void read_leases PROTO ((void));
int parse_statement PROTO ((FILE *,
			    struct group *, int, struct host_decl *, int));
void parse_failover_peer PROTO ((FILE *, struct group *, int));
enum failover_state parse_failover_state PROTO ((FILE *));
void parse_pool_statement PROTO ((FILE *, struct group *, int));
int parse_boolean PROTO ((FILE *));
int parse_lbrace PROTO ((FILE *));
void parse_host_declaration PROTO ((FILE *, struct group *));
struct class *parse_class_declaration PROTO ((FILE *, struct group *, int));
void parse_shared_net_declaration PROTO ((FILE *, struct group *));
void parse_subnet_declaration PROTO ((FILE *, struct shared_network *));
void parse_group_declaration PROTO ((FILE *, struct group *));
int parse_fixed_addr_param PROTO ((struct option_cache **, FILE *));
TIME parse_timestamp PROTO ((FILE *));
struct lease *parse_lease_declaration PROTO ((FILE *));
void parse_address_range PROTO ((FILE *, struct group *, int, struct pool *));

/* parse.c */
void skip_to_semi PROTO ((FILE *));
void skip_to_rbrace PROTO ((FILE *, int));
int parse_semi PROTO ((FILE *));
char *parse_string PROTO ((FILE *));
char *parse_host_name PROTO ((FILE *));
int parse_ip_addr_or_hostname PROTO ((struct expression **, FILE *, int));
void parse_hardware_param PROTO ((FILE *, struct hardware *));
void parse_lease_time PROTO ((FILE *, TIME *));
unsigned char *parse_numeric_aggregate PROTO ((FILE *,
					       unsigned char *, int *,
					       int, int, int));
void convert_num PROTO ((unsigned char *, char *, int, int));
TIME parse_date PROTO ((FILE *));
struct option *parse_option_name PROTO ((FILE *, int));
void parse_option_space_decl PROTO ((FILE *));
int parse_option_code_definition PROTO ((FILE *, struct option *));
int parse_cshl PROTO ((struct data_string *, FILE *));
struct executable_statement *parse_executable_statement PROTO ((FILE *,
								int *));
struct executable_statement *parse_executable_statements PROTO ((FILE *,
								 int *));
struct executable_statement *parse_if_statement PROTO ((FILE *, int *));
int parse_boolean_expression PROTO ((struct expression **, FILE *, int *));
int parse_data_expression PROTO ((struct expression **, FILE *, int *));
int parse_numeric_expression PROTO ((struct expression **, FILE *, int *));
int parse_non_binary PROTO ((struct expression **, FILE *, int *,
			     enum expression_context));
int parse_expression PROTO ((struct expression **, FILE *, int *,
			     enum expression_context,
			     struct expression **, enum expr_op));
struct executable_statement *parse_option_statement PROTO ((FILE *, int,
							    struct option *,
							    enum statement_op)
							   );
int parse_option_token PROTO ((struct expression **, FILE *, char *,
			       struct expression *, int, int));
int parse_allow_deny PROTO ((struct option_cache **, FILE *, int));
int parse_auth_key PROTO ((struct data_string *, FILE *));

/* tree.c */
pair cons PROTO ((caddr_t, pair));
int make_const_option_cache PROTO ((struct option_cache **, struct buffer **,
				    u_int8_t *, int, struct option *, char *));
int make_host_lookup PROTO ((struct expression **, char *));
int enter_dns_host PROTO ((struct dns_host_entry **, char *));
int make_const_data PROTO ((struct expression **,
			    unsigned char *, int, int, int));
int make_concat PROTO ((struct expression **,
			struct expression *, struct expression *));
int make_encapsulation PROTO ((struct expression **, struct data_string *));
int make_substring PROTO ((struct expression **, struct expression *,
			   struct expression *, struct expression *));
int make_limit PROTO ((struct expression **, struct expression *, int));
int option_cache PROTO ((struct option_cache **, struct data_string *,
			 struct expression *, struct option *));
int evaluate_boolean_expression PROTO ((int *,
					struct packet *, struct option_state *,
					struct lease *,
					struct expression *));
int evaluate_data_expression PROTO ((struct data_string *,
				     struct packet *, struct option_state *,
				     struct lease *,
				     struct expression *));
int evaluate_numeric_expression PROTO
	((unsigned long *, struct packet *,
	  struct option_state *, struct lease *, struct expression *));
int evaluate_option_cache PROTO ((struct data_string *,
				  struct packet *,
				  struct option_state *,
				  struct lease *,
				  struct option_cache *));
int evaluate_boolean_option_cache PROTO ((struct packet *,
					  struct option_state *,
					  struct lease *,
					  struct option_cache *));
int evaluate_boolean_expression_result PROTO ((struct packet *,
					       struct option_state *,
					       struct lease *,
					       struct expression *));
void expression_dereference PROTO ((struct expression **, char *));
void data_string_copy PROTO ((struct data_string *,
			      struct data_string *, char *));
void data_string_forget PROTO ((struct data_string *, char *));
void data_string_truncate PROTO ((struct data_string *, int));
int is_boolean_expression PROTO ((struct expression *));
int is_data_expression PROTO ((struct expression *));
int is_numeric_expression PROTO ((struct expression *));
int op_precedence PROTO ((enum expr_op, enum expr_op));
enum expression_context op_context PROTO ((enum expr_op));

/* dhcp.c */
extern int outstanding_pings;

void dhcp PROTO ((struct packet *));
void dhcpdiscover PROTO ((struct packet *));
void dhcprequest PROTO ((struct packet *));
void dhcprelease PROTO ((struct packet *));
void dhcpdecline PROTO ((struct packet *));
void dhcpinform PROTO ((struct packet *));
void nak_lease PROTO ((struct packet *, struct iaddr *cip));
void ack_lease PROTO ((struct packet *, struct lease *,
		       unsigned int, TIME, char *));
void dhcp_reply PROTO ((struct lease *));
struct lease *find_lease PROTO ((struct packet *,
				 struct shared_network *, int *));
struct lease *mockup_lease PROTO ((struct packet *,
				   struct shared_network *,
				   struct host_decl *));

struct lease *allocate_lease PROTO ((struct packet *, struct pool *, int));
int permitted PROTO ((struct packet *, struct permit *));

/* bootp.c */
void bootp PROTO ((struct packet *));

/* memory.c */
void enter_host PROTO ((struct host_decl *));
struct host_decl *find_hosts_by_haddr PROTO ((int, unsigned char *, int));
struct host_decl *find_hosts_by_uid PROTO ((unsigned char *, int));
struct subnet *find_host_for_network PROTO ((struct host_decl **,
					     struct iaddr *,
					     struct shared_network *));
void new_address_range PROTO ((struct iaddr, struct iaddr,
			       struct subnet *, struct pool *));
extern struct subnet *find_grouped_subnet PROTO ((struct shared_network *,
						  struct iaddr));
extern struct subnet *find_subnet PROTO ((struct iaddr));
void enter_shared_network PROTO ((struct shared_network *));
int subnet_inner_than PROTO ((struct subnet *, struct subnet *, int));
void enter_subnet PROTO ((struct subnet *));
void enter_lease PROTO ((struct lease *));
int supersede_lease PROTO ((struct lease *, struct lease *, int));
void release_lease PROTO ((struct lease *, struct packet *));
void abandon_lease PROTO ((struct lease *, struct packet *, char *));
void dissociate_lease PROTO ((struct lease *, struct packet *));
void pool_timer PROTO ((void *));
void expire_all_pools PROTO ((void));
struct lease *find_lease_by_uid PROTO ((unsigned char *, int));
struct lease *find_lease_by_hw_addr PROTO ((unsigned char *, int));
struct lease *find_lease_by_ip_addr PROTO ((struct iaddr));
void uid_hash_add PROTO ((struct lease *));
void uid_hash_delete PROTO ((struct lease *));
void hw_hash_add PROTO ((struct lease *));
void hw_hash_delete PROTO ((struct lease *));
struct group *clone_group PROTO ((struct group *, char *));
void write_leases PROTO ((void));
void dump_subnets PROTO ((void));

/* alloc.c */
VOIDPTR dmalloc PROTO ((int, char *));
void dfree PROTO ((VOIDPTR, char *));
struct packet *new_packet PROTO ((char *));
struct dhcp_packet *new_dhcp_packet PROTO ((char *));
struct hash_table *new_hash_table PROTO ((int, char *));
struct hash_bucket *new_hash_bucket PROTO ((char *));
struct lease *new_lease PROTO ((char *));
struct lease *new_leases PROTO ((int, char *));
struct subnet *new_subnet PROTO ((char *));
struct class *new_class PROTO ((char *));
struct shared_network *new_shared_network PROTO ((char *));
struct group *new_group PROTO ((char *));
struct protocol *new_protocol PROTO ((char *));
struct lease_state *new_lease_state PROTO ((char *));
struct domain_search_list *new_domain_search_list PROTO ((char *));
struct name_server *new_name_server PROTO ((char *));
void free_name_server PROTO ((struct name_server *, char *));
struct option *new_option PROTO ((char *));
void free_option PROTO ((struct option *, char *));
struct universe *new_universe PROTO ((char *));
void free_universe PROTO ((struct universe *, char *));
void free_domain_search_list PROTO ((struct domain_search_list *, char *));
void free_lease_state PROTO ((struct lease_state *, char *));
void free_protocol PROTO ((struct protocol *, char *));
void free_group PROTO ((struct group *, char *));
void free_shared_network PROTO ((struct shared_network *, char *));
void free_class PROTO ((struct class *, char *));
void free_subnet PROTO ((struct subnet *, char *));
void free_lease PROTO ((struct lease *, char *));
void free_hash_bucket PROTO ((struct hash_bucket *, char *));
void free_hash_table PROTO ((struct hash_table *, char *));
void free_packet PROTO ((struct packet *, char *));
void free_dhcp_packet PROTO ((struct dhcp_packet *, char *));
struct client_lease *new_client_lease PROTO ((char *));
void free_client_lease PROTO ((struct client_lease *, char *));
struct pool *new_pool PROTO ((char *));
void free_pool PROTO ((struct pool *, char *));
struct failover_peer *new_failover_peer PROTO ((char *));
void free_failover_peer PROTO ((struct failover_peer *, char *));
struct auth_key *new_auth_key PROTO ((int, char *));
void free_auth_key PROTO ((struct auth_key *, char *));
struct permit *new_permit PROTO ((char *));
void free_permit PROTO ((struct permit *, char *));
pair new_pair PROTO ((char *));
void free_pair PROTO ((pair, char *));
int expression_allocate PROTO ((struct expression **, char *));
int expression_reference PROTO ((struct expression **,
				 struct expression *, char *));
void free_expression PROTO ((struct expression *, char *));
int option_cache_allocate PROTO ((struct option_cache **, char *));
int option_cache_reference PROTO ((struct option_cache **,
				   struct option_cache *, char *));
int buffer_allocate PROTO ((struct buffer **, int, char *));
int buffer_reference PROTO ((struct buffer **, struct buffer *, char *));
int buffer_dereference PROTO ((struct buffer **, char *));
int dns_host_entry_allocate PROTO ((struct dns_host_entry **, char *, char *));
int dns_host_entry_reference PROTO ((struct dns_host_entry **,
				     struct dns_host_entry *, char *));
int dns_host_entry_dereference PROTO ((struct dns_host_entry **, char *));
int option_state_allocate PROTO ((struct option_state **, char *));
int option_state_reference PROTO ((struct option_state **,
				   struct option_state *, char *));
int option_state_dereference PROTO ((struct option_state **, char *));

/* print.c */
char *print_hw_addr PROTO ((int, int, unsigned char *));
void print_lease PROTO ((struct lease *));
void dump_raw PROTO ((unsigned char *, int));
void dump_packet PROTO ((struct packet *));
void hash_dump PROTO ((struct hash_table *));
char *print_hex_1 PROTO ((int, u_int8_t *, int));
char *print_hex_2 PROTO ((int, u_int8_t *, int));
char *print_hex_3 PROTO ((int, u_int8_t *, int));
char *print_dotted_quads PROTO ((int, u_int8_t *));
char *print_dec_1 PROTO ((int));
char *print_dec_2 PROTO ((int));
void print_expression PROTO ((char *, struct expression *));

/* socket.c */
#if defined (USE_SOCKET_SEND) || defined (USE_SOCKET_RECEIVE) \
	|| defined (USE_SOCKET_FALLBACK)
int if_register_socket PROTO ((struct interface_info *));
#endif

#if defined (USE_SOCKET_FALLBACK) && !defined (USE_SOCKET_SEND)
void if_reinitialize_fallback PROTO ((struct interface_info *));
void if_register_fallback PROTO ((struct interface_info *));
ssize_t send_fallback PROTO ((struct interface_info *,
			      struct packet *, struct dhcp_packet *, size_t, 
			      struct in_addr,
			      struct sockaddr_in *, struct hardware *));
#endif

#ifdef USE_SOCKET_SEND
void if_reinitialize_send PROTO ((struct interface_info *));
void if_register_send PROTO ((struct interface_info *));
ssize_t send_packet PROTO ((struct interface_info *,
			    struct packet *, struct dhcp_packet *, size_t, 
			    struct in_addr,
			    struct sockaddr_in *, struct hardware *));
#endif
#ifdef USE_SOCKET_RECEIVE
void if_reinitialize_receive PROTO ((struct interface_info *));
void if_register_receive PROTO ((struct interface_info *));
ssize_t receive_packet PROTO ((struct interface_info *,
			       unsigned char *, size_t,
			       struct sockaddr_in *, struct hardware *));
#endif

#if defined (USE_SOCKET_FALLBACK)
void fallback_discard PROTO ((struct protocol *));
#endif

#if defined (USE_SOCKET_SEND)
int can_unicast_without_arp PROTO ((struct interface_info *));
int can_receive_unicast_unconfigured PROTO ((struct interface_info *));
void maybe_setup_fallback PROTO ((void));
#endif

/* bpf.c */
#if defined (USE_BPF_SEND) || defined (USE_BPF_RECEIVE)
int if_register_bpf PROTO ( (struct interface_info *));
#endif
#ifdef USE_BPF_SEND
void if_reinitialize_send PROTO ((struct interface_info *));
void if_register_send PROTO ((struct interface_info *));
ssize_t send_packet PROTO ((struct interface_info *,
			    struct packet *, struct dhcp_packet *, size_t,
			    struct in_addr,
			    struct sockaddr_in *, struct hardware *));
#endif
#ifdef USE_BPF_RECEIVE
void if_reinitialize_receive PROTO ((struct interface_info *));
void if_register_receive PROTO ((struct interface_info *));
ssize_t receive_packet PROTO ((struct interface_info *,
			       unsigned char *, size_t,
			       struct sockaddr_in *, struct hardware *));
#endif
#if defined (USE_BPF_SEND)
int can_unicast_without_arp PROTO ((struct interface_info *));
int can_receive_unicast_unconfigured PROTO ((struct interface_info *));
void maybe_setup_fallback PROTO ((void));
#endif

/* lpf.c */
#if defined (USE_LPF_SEND) || defined (USE_LPF_RECEIVE)
int if_register_lpf PROTO ( (struct interface_info *));
#endif
#ifdef USE_LPF_SEND
void if_reinitialize_send PROTO ((struct interface_info *));
void if_register_send PROTO ((struct interface_info *));
ssize_t send_packet PROTO ((struct interface_info *,
			    struct packet *, struct dhcp_packet *, size_t,
			    struct in_addr,
			    struct sockaddr_in *, struct hardware *));
#endif
#ifdef USE_LPF_RECEIVE
void if_reinitialize_receive PROTO ((struct interface_info *));
void if_register_receive PROTO ((struct interface_info *));
ssize_t receive_packet PROTO ((struct interface_info *,
			       unsigned char *, size_t,
			       struct sockaddr_in *, struct hardware *));
#endif
#if defined (USE_LPF_SEND)
int can_unicast_without_arp PROTO ((struct interface_info *));
int can_receive_unicast_unconfigured PROTO ((struct interface_info *));
void maybe_setup_fallback PROTO ((void));
#endif

/* nit.c */
#if defined (USE_NIT_SEND) || defined (USE_NIT_RECEIVE)
int if_register_nit PROTO ( (struct interface_info *));
#endif

#ifdef USE_NIT_SEND
void if_reinitialize_send PROTO ((struct interface_info *));
void if_register_send PROTO ((struct interface_info *));
ssize_t send_packet PROTO ((struct interface_info *,
			    struct packet *, struct dhcp_packet *, size_t,
			    struct in_addr,
			    struct sockaddr_in *, struct hardware *));
#endif
#ifdef USE_NIT_RECEIVE
void if_reinitialize_receive PROTO ((struct interface_info *));
void if_register_receive PROTO ((struct interface_info *));
ssize_t receive_packet PROTO ((struct interface_info *,
			       unsigned char *, size_t,
			       struct sockaddr_in *, struct hardware *));
#endif
#if defined (USE_NIT_SEND)
int can_unicast_without_arp PROTO ((struct interface_info *));
int can_receive_unicast_unconfigured PROTO ((struct interface_info *));
void maybe_setup_fallback PROTO ((void));
#endif

/* dlpi.c */
#if defined (USE_DLPI_SEND) || defined (USE_DLPI_RECEIVE)
int if_register_dlpi PROTO ( (struct interface_info *));
#endif

#ifdef USE_DLPI_SEND
void if_reinitialize_send PROTO ((struct interface_info *));
void if_register_send PROTO ((struct interface_info *));
ssize_t send_packet PROTO ((struct interface_info *,
			    struct packet *, struct dhcp_packet *, size_t,
			    struct in_addr,
			    struct sockaddr_in *, struct hardware *));
#endif
#ifdef USE_DLPI_RECEIVE
void if_reinitialize_receive PROTO ((struct interface_info *));
void if_register_receive PROTO ((struct interface_info *));
ssize_t receive_packet PROTO ((struct interface_info *,
			       unsigned char *, size_t,
			       struct sockaddr_in *, struct hardware *));
#endif


/* raw.c */
#ifdef USE_RAW_SEND
void if_reinitialize_send PROTO ((struct interface_info *));
void if_register_send PROTO ((struct interface_info *));
ssize_t send_packet PROTO ((struct interface_info *,
			    struct packet *, struct dhcp_packet *, size_t,
			    struct in_addr,
			    struct sockaddr_in *, struct hardware *));
int can_unicast_without_arp PROTO ((struct interface_info *));
int can_receive_unicast_unconfigured PROTO ((struct interface_info *));
void maybe_setup_fallback PROTO ((void));
#endif

/* dispatch.c */
extern struct interface_info *interfaces,
	*dummy_interfaces, *fallback_interface;
extern struct protocol *protocols;
extern int quiet_interface_discovery;
extern void (*bootp_packet_handler) PROTO ((struct interface_info *,
					    struct dhcp_packet *, int,
					    unsigned int,
					    struct iaddr, struct hardware *));
extern struct timeout *timeouts;
void discover_interfaces PROTO ((int));
struct interface_info *setup_fallback PROTO ((void));
void reinitialize_interfaces PROTO ((void));
void dispatch PROTO ((void));
int locate_network PROTO ((struct packet *));
void got_one PROTO ((struct protocol *));
void add_timeout PROTO ((TIME, void (*) PROTO ((void *)), void *));
void cancel_timeout PROTO ((void (*) PROTO ((void *)), void *));
struct protocol *add_protocol PROTO ((char *, int,
				      void (*) PROTO ((struct protocol *)),
				      void *));

void remove_protocol PROTO ((struct protocol *));

/* hash.c */
struct hash_table *new_hash PROTO ((void));
void add_hash PROTO ((struct hash_table *,
		      unsigned char *, int, unsigned char *));
void delete_hash_entry PROTO ((struct hash_table *, unsigned char *, int));
unsigned char *hash_lookup PROTO ((struct hash_table *, unsigned char *, int));

/* tables.c */
extern struct universe dhcp_universe;
extern struct option dhcp_options [256];
extern struct universe agent_universe;
extern struct option agent_options [256];
extern struct universe server_universe;
extern struct option server_options [256];
extern int dhcp_option_default_priority_list [];
extern int dhcp_option_default_priority_list_count;
extern char *hardware_types [256];
int universe_count, universe_max;
struct universe **universes;
extern struct hash_table universe_hash;
void initialize_universes PROTO ((void));

/* convert.c */
u_int32_t getULong PROTO ((unsigned char *));
int32_t getLong PROTO ((unsigned char *));
u_int32_t getUShort PROTO ((unsigned char *));
int32_t getShort PROTO ((unsigned char *));
u_int32_t getUChar PROTO ((unsigned char *));
void putULong PROTO ((unsigned char *, u_int32_t));
void putLong PROTO ((unsigned char *, int32_t));
void putUShort PROTO ((unsigned char *, u_int32_t));
void putShort PROTO ((unsigned char *, int32_t));
void putUChar PROTO ((unsigned char *, u_int32_t));
int converted_length PROTO ((unsigned char *, unsigned int, unsigned int));
int binary_to_ascii PROTO ((unsigned char *, unsigned char *,
			    unsigned int, unsigned int));

/* inet.c */
struct iaddr subnet_number PROTO ((struct iaddr, struct iaddr));
struct iaddr ip_addr PROTO ((struct iaddr, struct iaddr, u_int32_t));
struct iaddr broadcast_addr PROTO ((struct iaddr, struct iaddr));
u_int32_t host_addr PROTO ((struct iaddr, struct iaddr));
int addr_eq PROTO ((struct iaddr, struct iaddr));
char *piaddr PROTO ((struct iaddr));

/* dhclient.c */
extern char *path_dhclient_conf;
extern char *path_dhclient_db;
extern char *path_dhclient_pid;
extern int interfaces_requested;

extern struct client_config top_level_config;

void dhcpoffer PROTO ((struct packet *));
void dhcpack PROTO ((struct packet *));
void dhcpnak PROTO ((struct packet *));

void send_discover PROTO ((void *));
void send_request PROTO ((void *));
void send_release PROTO ((void *));
void send_decline PROTO ((void *));

void state_reboot PROTO ((void *));
void state_init PROTO ((void *));
void state_selecting PROTO ((void *));
void state_requesting PROTO ((void *));
void state_bound PROTO ((void *));
void state_panic PROTO ((void *));

void bind_lease PROTO ((struct client_state *));

void make_client_options PROTO ((struct client_state *,
				 struct client_lease *, u_int8_t *,
				 struct option_cache *, struct iaddr *,
				 u_int32_t *, struct option_state **));
void make_discover PROTO ((struct client_state *, struct client_lease *));
void make_request PROTO ((struct client_state *, struct client_lease *));
void make_decline PROTO ((struct client_state *, struct client_lease *));
void make_release PROTO ((struct client_state *, struct client_lease *));

void destroy_client_lease PROTO ((struct client_lease *));
void rewrite_client_leases PROTO ((void));
void write_client_lease PROTO ((struct client_state *,
				 struct client_lease *, int));
char *dhcp_option_ev_name PROTO ((struct option *));

void script_init PROTO ((struct client_state *, char *,
			 struct string_list *));
void script_write_params PROTO ((struct client_state *,
				 char *, struct client_lease *));
int script_go PROTO ((struct client_state *));

struct client_lease *packet_to_lease PROTO ((struct packet *));
void go_daemon PROTO ((void));
void write_client_pid_file PROTO ((void));
void client_location_changed PROTO ((void));

/* db.c */
int write_lease PROTO ((struct lease *));
int db_printable PROTO ((char *));
int write_billing_class PROTO ((struct class *));
int commit_leases PROTO ((void));
void db_startup PROTO ((int));
void new_lease_file PROTO ((void));

/* packet.c */
u_int32_t checksum PROTO ((unsigned char *, int, u_int32_t));
u_int32_t wrapsum PROTO ((u_int32_t));
void assemble_hw_header PROTO ((struct interface_info *, unsigned char *,
				int *, struct hardware *));
void assemble_udp_ip_header PROTO ((struct interface_info *, unsigned char *,
				    int *, u_int32_t, u_int32_t, u_int32_t,
				    unsigned char *, int));
ssize_t decode_hw_header PROTO ((struct interface_info *, unsigned char *,
				 int, struct hardware *));
ssize_t decode_udp_ip_header PROTO ((struct interface_info *, unsigned char *,
				     int, struct sockaddr_in *,
				     unsigned char *, int));

/* ethernet.c */
void assemble_ethernet_header PROTO ((struct interface_info *, unsigned char *,
				      int *, struct hardware *));
ssize_t decode_ethernet_header PROTO ((struct interface_info *,
				       unsigned char *,
				       int, struct hardware *));

/* tr.c */
void assemble_tr_header PROTO ((struct interface_info *, unsigned char *,
				int *, struct hardware *));
ssize_t decode_tr_header PROTO ((struct interface_info *,
				 unsigned char *,
				 int, struct hardware *));

/* dhxpxlt.c */
void convert_statement PROTO ((FILE *));
void convert_host_statement PROTO ((FILE *, jrefproto));
void convert_host_name PROTO ((FILE *, jrefproto));
void convert_class_statement PROTO ((FILE *, jrefproto, int));
void convert_class_decl PROTO ((FILE *, jrefproto));
void convert_lease_time PROTO ((FILE *, jrefproto, char *));
void convert_shared_net_statement PROTO ((FILE *, jrefproto));
void convert_subnet_statement PROTO ((FILE *, jrefproto));
void convert_subnet_decl PROTO ((FILE *, jrefproto));
void convert_host_decl PROTO ((FILE *, jrefproto));
void convert_hardware_decl PROTO ((FILE *, jrefproto));
void convert_hardware_addr PROTO ((FILE *, jrefproto));
void convert_filename_decl PROTO ((FILE *, jrefproto));
void convert_servername_decl PROTO ((FILE *, jrefproto));
void convert_ip_addr_or_hostname PROTO ((FILE *, jrefproto, int));
void convert_fixed_addr_decl PROTO ((FILE *, jrefproto));
void convert_option_decl PROTO ((FILE *, jrefproto));
void convert_timestamp PROTO ((FILE *, jrefproto));
void convert_lease_statement PROTO ((FILE *, jrefproto));
void convert_address_range PROTO ((FILE *, jrefproto));
void convert_date PROTO ((FILE *, jrefproto, char *));
void convert_numeric_aggregate PROTO ((FILE *, jrefproto, int, int, int, int));
void indent PROTO ((int));

/* route.c */
void add_route_direct PROTO ((struct interface_info *, struct in_addr));
void add_route_net PROTO ((struct interface_info *, struct in_addr,
			   struct in_addr));
void add_route_default_gateway PROTO ((struct interface_info *, 
				       struct in_addr));
void remove_routes PROTO ((struct in_addr));
void remove_if_route PROTO ((struct interface_info *, struct in_addr));
void remove_all_if_routes PROTO ((struct interface_info *));
void set_netmask PROTO ((struct interface_info *, struct in_addr));
void set_broadcast_addr PROTO ((struct interface_info *, struct in_addr));
void set_ip_address PROTO ((struct interface_info *, struct in_addr));

/* clparse.c */
int read_client_conf PROTO ((void));
void read_client_leases PROTO ((void));
void parse_client_statement PROTO ((FILE *, struct interface_info *,
				    struct client_config *));
int parse_X PROTO ((FILE *, u_int8_t *, int));
void parse_option_list PROTO ((FILE *, u_int32_t **));
void parse_interface_declaration PROTO ((FILE *,
					 struct client_config *, char *));
struct interface_info *interface_or_dummy PROTO ((char *));
void make_client_state PROTO ((struct client_state **));
void make_client_config PROTO ((struct client_state *,
				struct client_config *));
void parse_client_lease_statement PROTO ((FILE *, int));
void parse_client_lease_declaration PROTO ((FILE *, struct client_lease *,
					    struct interface_info **,
					    struct client_state **));
int parse_option_decl PROTO ((struct option_cache **, FILE *));
void parse_string_list PROTO ((FILE *, struct string_list **, int));
int parse_ip_addr PROTO ((FILE *, struct iaddr *));
void parse_reject_statement PROTO ((FILE *, struct client_config *));

/* dhcrelay.c */
void relay PROTO ((struct interface_info *, struct dhcp_packet *, int,
		   unsigned int, struct iaddr, struct hardware *));
int strip_relay_agent_options PROTO ((struct interface_info *,
				      struct interface_info **,
				      struct dhcp_packet *, int));
int find_interface_by_agent_option PROTO ((struct dhcp_packet *,
					   struct interface_info **,
					   u_int8_t *, int));
int add_relay_agent_options PROTO ((struct interface_info *ip,
				    struct dhcp_packet *packet,
				    int length, struct in_addr giaddr));

/* icmp.c */
void icmp_startup PROTO ((int, void (*) PROTO ((struct iaddr,
						u_int8_t *, int))));
int icmp_echorequest PROTO ((struct iaddr *));
void icmp_echoreply PROTO ((struct protocol *));

/* dns.c */
void dns_startup PROTO ((void));
struct dns_query *find_dns_query PROTO ((struct dns_question *, int));
void destroy_dns_query PROTO ((struct dns_query *));
struct dns_query *ns_inaddr_lookup PROTO ((struct iaddr, struct dns_wakeup *));
struct dns_query *ns_query PROTO ((struct dns_question *,
				   unsigned char *, int, struct dns_wakeup *));
void dns_timeout PROTO ((void *));
void dns_packet PROTO ((struct protocol *));

/* resolv.c */
extern char path_resolv_conf [];
struct name_server *name_servers;
struct domain_search_list *domains;

void read_resolv_conf PROTO ((TIME));
struct name_server *first_name_server PROTO ((void));

/* inet_addr.c */
#ifdef NEED_INET_ATON
int inet_aton PROTO ((const char *, struct in_addr *));
#endif

/* class.c */
extern int have_billing_classes;
struct class unknown_class;
struct class known_class;
struct collection default_collection;
struct collection *collections;
struct executable_statement *default_classification_rules;

void classification_setup PROTO ((void));
void classify_client PROTO ((struct packet *));
int check_collection PROTO ((struct packet *, struct lease *,
			     struct collection *));
void classify PROTO ((struct packet *, struct class *));
struct class *find_class PROTO ((char *));
int unbill_class PROTO ((struct lease *, struct class *));
int bill_class PROTO ((struct lease *, struct class *));

/* execute.c */
int execute_statements PROTO ((struct packet *,
			       struct lease *,
			       struct option_state *, struct option_state *,
			       struct executable_statement *));
void execute_statements_in_scope PROTO ((struct packet *,
					 struct lease *,
					 struct option_state *,
					 struct option_state *,
					 struct group *, struct group *));

/* auth.c */
void enter_auth_key PROTO ((struct data_string *, struct auth_key *));
struct auth_key *auth_key_lookup PROTO ((struct data_string *));

/* failover.c */
void enter_failover_peer PROTO ((struct failover_peer *));
struct failover_peer *find_failover_peer PROTO ((char *));

/* nsupdate.c */

char *ddns_rev_name PROTO ((struct lease *,
			    struct lease_state *, struct packet *));
char *ddns_fwd_name PROTO ((struct lease *,
			    struct lease_state *, struct packet *));
int nsupdateA PROTO ((char *, char *, u_int32_t, int));
int nsupdatePTR PROTO ((char *, char *, u_int32_t, int));
void nsupdate PROTO ((struct lease *,
		      struct lease_state *, struct packet *, int));
