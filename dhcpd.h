/* dhcpd.h

   Definitions for dhcpd... */

/*
 * Copyright (c) 1995, 1996 The Internet Software Consortium.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of The Internet Software Consortium nor the names
 *    of its contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INTERNET SOFTWARE CONSORTIUM AND
 * CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE INTERNET SOFTWARE CONSORTIUM OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This software has been written for the Internet Software Consortium
 * by Ted Lemon <mellon@fugue.com> in cooperation with Vixie
 * Enterprises.  To learn more about the Internet Software Consortium,
 * see ``http://www.vix.com/isc''.  To learn more about Vixie
 * Enterprises, see ``http://www.vix.com''.
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <ctype.h>
#include <time.h>

#include "cdefs.h"
#include "osdep.h"
#include "dhcp.h"
#include "tree.h"
#include "hash.h"
#include "inet.h"

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
	struct subnet *subnet;		/* Subnet of client. */
	struct {
		int len;
		unsigned char *data;
	} options [256];
};

struct hardware {
	u_int8_t htype;
	u_int8_t hlen;
	u_int8_t haddr [16];
};

/* A dhcp host declaration structure. */
struct host_decl {
	struct host_decl *n_name, *n_haddr, *n_cid;
	char *name;
	struct hardware *interfaces;
	int interface_count;
	char *filename;
	char *server_name;	
	struct tree_cache *fixed_addr;
	struct tree_cache *ciaddr;
	struct tree_cache *yiaddr;
	struct tree_cache *siaddr;
	struct tree_cache *giaddr;
	struct tree_cache *options [256];
};

/* A dhcp lease declaration structure. */
struct lease {
	struct lease *next;
	struct lease *prev;
	struct iaddr ip_addr;
	TIME starts, ends, timestamp;
	TIME offered_expiry;
	unsigned char *uid;
	int uid_len;
	struct host_decl *host;
	struct subnet *contain;
	struct hardware hardware_addr;
	int state;
	int xid;
};

struct subnet {
	struct subnet *next;
	struct iaddr net;
	struct iaddr netmask;
	TIME default_lease_time;
	TIME max_lease_time;
	struct tree_cache *options [256];
	struct lease *leases;
	struct lease *insertion_point;
	struct lease *last_lease;
};

struct class {
	char *name;
	char *filename;
	TIME default_lease_time;
	TIME max_lease_time;
	struct tree_cache *options [256];
};

/* Information about each network interface. */

struct interface_info {
	struct interface_info *next;	/* Next interface in list... */
	struct subnet *local_subnet;	/* This interface's subnet. */
	struct iaddr address;		/* Its IP address. */
	struct hardware hw_address;	/* Its physical address. */
	char name [IFNAMSIZ];		/* Its name... */
	int rfdesc;			/* Its read file descriptor. */
	int wfdesc;			/* Its write file descriptor, if
					   different. */
	unsigned char *rbuf;		/* Read buffer, if required. */
	size_t rbuf_max;		/* Size of read buffer. */
	size_t rbuf_offset;		/* Current offset into buffer. */
	size_t rbuf_len;		/* Length of data in buffer. */
};

struct hardware_link {
	struct hardware_link *next;
	char name [IFNAMSIZ];
	struct hardware address;
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
#define _PATH_DHCPD_CONF	"dhcpd.conf"
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

#define MAX_TIME 0x7fffffff
#define MIN_TIME 0

/* External definitions... */

/* options.c */

void parse_options PROTO ((struct packet *));
void parse_option_buffer PROTO ((struct packet *, unsigned char *, int));
void cons_options PROTO ((struct packet *, struct packet *,
			  struct tree_cache **, int));
/* void new_cons_options PROTO ((struct packet *, struct packet *,
			  struct tree_cache **, int)); */
int store_options PROTO ((unsigned char *, int, struct tree_cache **,
			   unsigned char *, int, int, int));
/* int store_option PROTO ((struct tree_cache **, unsigned char,
			 unsigned char *, int, int *)); */
char *pretty_print_option PROTO ((unsigned char, unsigned char *, int));

/* errwarn.c */
int error PROTO ((char *, ...));
int warn PROTO ((char *, ...));
int note PROTO ((char *, ...));
int debug PROTO ((char *, ...));
int parse_warn PROTO ((char *, ...));

/* dhcpd.c */
TIME cur_time;
TIME default_lease_time;
TIME max_lease_time;

extern u_int16_t server_port;
extern int log_priority;

int main PROTO ((int, char **, char **));
void cleanup PROTO ((void));
void do_packet PROTO ((struct interface_info *,
		       unsigned char *, int,
		       unsigned short, struct iaddr, struct hardware *));


/* conflex.c */
int next_token PROTO ((char **, FILE *));
int peek_token PROTO ((char **, FILE *));

/* confpars.c */
void readconf PROTO ((void));
void read_leases PROTO ((void));
void parse_statement PROTO ((FILE *));
void skip_to_semi PROTO ((FILE *));
struct host_decl *parse_host_statement PROTO ((FILE *, jrefproto));
char *parse_host_name PROTO ((FILE *, jrefproto));
void parse_class_statement PROTO ((FILE *, jrefproto, int));
void parse_class_decl PROTO ((FILE *, jrefproto, struct class *));
struct subnet *parse_subnet_statement PROTO ((FILE *, jrefproto));
void parse_subnet_decl PROTO ((FILE *, jrefproto, struct subnet *));
void parse_host_decl PROTO ((FILE *, jrefproto, struct host_decl *));
void parse_hardware_decl PROTO ((FILE *, jrefproto, struct host_decl *));
struct hardware parse_hardware_addr PROTO ((FILE *, jrefproto));
char *parse_filename_decl PROTO ((FILE *, jrefproto));
struct tree *parse_ip_addr_or_hostname PROTO ((FILE *, jrefproto, int));
void parse_fixed_addr_decl PROTO ((FILE *, jrefproto, struct host_decl *));
void parse_option_decl PROTO ((FILE *, jrefproto, struct tree_cache **));
TIME parse_timestamp PROTO ((FILE *, jrefproto));
TIME parse_date PROTO ((FILE *, jrefproto));
struct lease *parse_lease_statement PROTO ((FILE *, jrefproto));
void parse_address_range PROTO ((FILE *, jrefproto, struct subnet *));
unsigned char *parse_numeric_aggregate PROTO ((FILE *, jrefproto,
					       unsigned char *, int *,
					       int, int, int));
void convert_num PROTO ((unsigned char *, char *, int, int));

/* tree.c */
pair cons PROTO ((caddr_t, pair));
struct tree_cache *tree_cache PROTO ((struct tree *));
struct tree *tree_host_lookup PROTO ((char *));
struct dns_host_entry *enter_dns_host PROTO ((char *));
struct tree *tree_const PROTO ((unsigned char *, int));
struct tree *tree_concat PROTO ((struct tree *, struct tree *));
struct tree *tree_limit PROTO ((struct tree *, int));
int tree_evaluate PROTO ((struct tree_cache *));

/* dhcp.c */
void dhcp PROTO ((struct packet *));
void dhcpdiscover PROTO ((struct packet *));
void dhcprequest PROTO ((struct packet *));
void dhcprelease PROTO ((struct packet *));
void dhcpdecline PROTO ((struct packet *));
void dhcpinform PROTO ((struct packet *));
void nak_lease PROTO ((struct packet *, struct iaddr *cip));
void ack_lease PROTO ((struct packet *, struct lease *, unsigned char, TIME));
struct lease *find_lease PROTO ((struct packet *));

/* bootp.c */
void bootp PROTO ((struct packet *));

/* memory.c */
void enter_host PROTO ((struct host_decl *));
struct host_decl *find_host_by_name PROTO ((char *name));
struct host_decl *find_host_by_addr PROTO ((int, unsigned char *, int));
void new_address_range PROTO ((struct iaddr, struct iaddr,
			       struct subnet *));
extern struct subnet *find_subnet PROTO ((struct iaddr));
void enter_subnet PROTO ((struct subnet *));
void enter_lease PROTO ((struct lease *));
int supersede_lease PROTO ((struct lease *, struct lease *, int));
void release_lease PROTO ((struct lease *));
void abandon_lease PROTO ((struct lease *));
struct lease *find_lease_by_uid PROTO ((unsigned char *, int));
struct lease *find_lease_by_hw_addr PROTO ((unsigned char *, int));
struct lease *find_lease_by_ip_addr PROTO ((struct iaddr));
struct class *add_class PROTO ((int, char *));
struct class *find_class PROTO ((int, char *, int));
void write_leases PROTO ((void));
void dump_subnets PROTO ((void));

/* alloc.c */
VOIDPTR dmalloc PROTO ((int, char *));
void dfree PROTO ((VOIDPTR, char *));
struct packet *new_packet PROTO ((char *));
struct dhcp_packet *new_dhcp_packet PROTO ((char *));
struct tree *new_tree PROTO ((char *));
struct tree_cache *new_tree_cache PROTO ((char *));
struct hash_table *new_hash_table PROTO ((int, char *));
struct hash_bucket *new_hash_bucket PROTO ((char *));
struct lease *new_lease PROTO ((char *));
struct lease *new_leases PROTO ((int, char *));
struct subnet *new_subnet PROTO ((char *));
struct class *new_class PROTO ((char *));
void free_class PROTO ((struct class *, char *));
void free_subnet PROTO ((struct subnet *, char *));
void free_lease PROTO ((struct lease *, char *));
void free_hash_bucket PROTO ((struct hash_bucket *, char *));
void free_hash_table PROTO ((struct hash_table *, char *));
void free_tree_cache PROTO ((struct tree_cache *, char *));
void free_packet PROTO ((struct packet *, char *));
void free_dhcp_packet PROTO ((struct dhcp_packet *, char *));
void free_tree PROTO ((struct tree *, char *));

/* print.c */
char *print_hw_addr PROTO ((int, int, unsigned char *));
void print_lease PROTO ((struct lease *));
void dump_raw PROTO ((unsigned char *, int));
void dump_packet PROTO ((struct packet *));

/* socket.c */
#if defined (USE_SOCKET_SEND) || defined (USE_SOCKET_RECEIVE)
int if_register_socket PROTO ((struct interface_info *, struct ifreq *));
#endif

#ifdef USE_SOCKET_SEND
void if_register_send PROTO ((struct interface_info *, struct ifreq *));
size_t send_packet PROTO ((struct interface_info *,
			   struct packet *, struct dhcp_packet *,
			   size_t, struct sockaddr_in *, struct hardware *));
#endif
#ifdef USE_SOCKET_RECEIVE
void if_register_receive PROTO ((struct interface_info *, struct ifreq *));
size_t receive_packet PROTO ((struct interface_info *,
			   unsigned char *, size_t,
			   struct sockaddr_in *, struct hardware *));
#endif

/* bpf.c */
#if defined (USE_BPF_SEND) || defined (USE_BPF_RECEIVE)
int if_register_bpf PROTO ( (struct interface_info *, struct ifreq *));
#endif
#ifdef USE_BPF_SEND
void if_register_send PROTO ((struct interface_info *, struct ifreq *));
size_t send_packet PROTO ((struct interface_info *,
			   struct packet *, struct dhcp_packet *,
			   size_t, struct sockaddr_in *, struct hardware *));
#endif
#ifdef USE_BPF_RECEIVE
void if_register_receive PROTO ((struct interface_info *, struct ifreq *));
size_t receive_packet PROTO ((struct interface_info *,
			   unsigned char *, size_t,
			   struct sockaddr_in *, struct hardware *));
#endif

/* nit.c */
#ifdef USE_NIT_SEND
void if_register_send PROTO ((struct interface_info *, struct ifreq *));
size_t send_packet PROTO ((struct interface_info *,
			   struct packet *, struct dhcp_packet *,
			   size_t, struct sockaddr_in *, struct hardware *));
#endif
#ifdef USE_NIT_RECEIVE
void if_register_receive PROTO ((struct interface_info *, struct ifreq *));
size_t receive_packet PROTO ((struct interface_info *,
			   unsigned char *, size_t,
			   struct sockaddr_in *, struct hardware *));
#endif

/* raw.c */
#ifdef USE_RAW_SEND
void if_register_send PROTO ((struct interface_info *, struct ifreq *));
size_t send_packet PROTO ((struct interface_info *,
			   struct packet *, struct dhcp_packet *,
			   size_t, struct sockaddr_in *, struct hardware *));
#endif

/* dispatch.c */
struct interface_info *interfaces;
void discover_interfaces PROTO ((void));
void dispatch PROTO ((void));

/* hash.c */
struct hash_table *new_hash PROTO ((void));
void add_hash PROTO ((struct hash_table *, char *, int, unsigned char *));
void delete_hash_entry PROTO ((struct hash_table *, char *, int));
unsigned char *hash_lookup PROTO ((struct hash_table *, char *, int));

/* tables.c */
extern struct option dhcp_options [256];
extern unsigned char dhcp_option_default_priority_list [];
extern int sizeof_dhcp_option_default_priority_list;
extern char *hardware_types [256];
extern struct hash_table universe_hash;
extern struct universe dhcp_universe;
void initialize_universes PROTO ((void));

/* convert.c */
unsigned long getULong PROTO ((unsigned char *));
long getLong PROTO ((unsigned char *));
unsigned short getUShort PROTO ((unsigned char *));
short getShort PROTO ((unsigned char *));
void putULong PROTO ((unsigned char *, unsigned long));
void putLong PROTO ((unsigned char *, long));
void putUShort PROTO ((unsigned char *, unsigned short));
void putShort PROTO ((unsigned char *, short));

/* inet.c */
struct iaddr subnet_number PROTO ((struct iaddr, struct iaddr));
struct iaddr ip_addr PROTO ((struct iaddr, struct iaddr, unsigned long));
unsigned long host_addr PROTO ((struct iaddr, struct iaddr));
int addr_eq PROTO ((struct iaddr, struct iaddr));
char *piaddr PROTO ((struct iaddr));

/* dhclient.c */
void parse_client_statement PROTO ((FILE *, struct host_decl *));

/* db.c */
int write_lease PROTO ((struct lease *));
int commit_leases PROTO ((void));
void db_startup PROTO ((void));
void new_lease_file PROTO ((void));

/* packet.c */
void assemble_hw_header PROTO ((struct interface_info *, unsigned char *,
				int *, struct hardware *));
void assemble_udp_ip_header PROTO ((struct interface_info *, unsigned char *,
				    int *, u_int32_t, u_int16_t,
				    unsigned char *, int));
size_t decode_hw_header PROTO ((struct interface_info *, unsigned char *,
				int, struct hardware *));
size_t decode_udp_ip_header PROTO ((struct interface_info *, unsigned char *,
				    int, struct sockaddr_in *,
				    unsigned char *, int));
