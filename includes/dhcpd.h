/* dhcpd.h

   Definitions for dhcpd... */

/*
 * Copyright (c) 1995 The Internet Software Consortium.  All rights reserved.
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
#include <syslog.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <malloc.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <ctype.h>

#include "dhcp.h"
#include "cdefs.h"
#include "osdep.h"
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
	int client_sock;
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
	struct tree_cache *options [256];
};

/* A dhcp lease declaration structure. */
struct lease {
	struct lease *next;
	struct lease *prev;
	struct iaddr ip_addr;
	TIME starts, ends, timestamp;
	unsigned char *uid;
	int uid_len;
	struct host_decl *host;
	struct subnet *contain;
	struct hardware hardware_addr;
	int state;
};

struct subnet {
	struct iaddr net;
	struct iaddr netmask;
	struct lease *leases;
	struct lease *insertion_point;
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
#ifndef _PATH_DHCPD_CONF
#ifdef DEBUG
#define _PATH_DHCPD_CONF	"dhcpd.conf"
#else
#define _PATH_DHCPD_CONF	"/etc/dhcpd.conf"
#endif
#endif

#define MAX_TIME 0x7fffffff
#define MIN_TIME 0

/* External definitions... */

/* options.c */

void parse_options PROTO ((struct packet *));
void parse_option_buffer PROTO ((struct packet *, unsigned char *, int));
void cons_options PROTO ((struct packet *, struct packet *,
			  struct host_decl *, int));
int store_option PROTO ((struct packet *, unsigned char,
			 unsigned char *, int, int *));
char *pretty_print_option PROTO ((unsigned char, unsigned char *, int));

/* errwarn.c */
int error PROTO ((char *, ...));
int warn PROTO ((char *, ...));
int note PROTO ((char *, ...));
int debug PROTO ((char *, ...));
int parse_warn PROTO ((char *, ...));

/* dhcpd.c */
TIME cur_time;
extern u_int32_t *server_addrlist;
extern int server_addrcount;
extern u_int16_t server_port;
int main PROTO ((int, char **, char **));
void cleanup PROTO ((void));
void do_packet PROTO ((unsigned char *, int,
		       unsigned long, struct iaddr, int));
void dump_packet PROTO ((struct packet *));
u_int32_t pick_interface PROTO ((struct packet *));


/* conflex.c */
int next_token PROTO ((char **, FILE *));
int peek_token PROTO ((char **, FILE *));

/* confpars.c */
void readconf PROTO ((void));
void parse_statement PROTO ((FILE *));
void skip_to_semi PROTO ((FILE *));
struct host_decl *parse_host_statement PROTO ((FILE *, jmp_buf *));
char *parse_host_name PROTO ((FILE *, jmp_buf *));
void parse_host_decl PROTO ((FILE *, jmp_buf *, struct host_decl *));
void parse_hardware_decl PROTO ((FILE *, jmp_buf *, struct host_decl *));
struct hardware parse_hardware_addr PROTO ((FILE *, jmp_buf *));
void parse_filename_decl PROTO ((FILE *, jmp_buf *, struct host_decl *));
struct tree *parse_ip_addr_or_hostname PROTO ((FILE *, jmp_buf *, int));
void parse_fixed_addr_decl PROTO ((FILE *, jmp_buf *, struct host_decl *));
void parse_option_decl PROTO ((FILE *, jmp_buf *, struct host_decl *));
TIME parse_timestamp PROTO ((FILE *, jmp_buf *));
TIME parse_date PROTO ((FILE *, jmp_buf *));
struct lease *parse_lease_statement PROTO ((FILE *, jmp_buf *));
void parse_address_range PROTO ((FILE *, jmp_buf *));
unsigned char *parse_numeric_aggregate PROTO ((FILE *, jmp_buf *,
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

/* bootp.c */
void bootp PROTO ((struct packet *));

/* memory.c */
void enter_host PROTO ((struct host_decl *));
struct host_decl *find_host_by_name PROTO ((char *name));
struct host_decl *find_host_by_addr PROTO ((int, unsigned char *, int));
void new_address_range PROTO ((struct iaddr, struct iaddr,
			       struct iaddr));
extern struct subnet *find_subnet (struct iaddr);
void enter_subnet (struct subnet *);
void enter_lease PROTO ((struct lease *));
void supersede_lease PROTO ((struct lease *, struct lease *));
struct lease *find_lease_by_uid PROTO ((unsigned char *, int));
struct lease *find_lease_by_ip_addr PROTO ((struct iaddr));

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
struct lease *new_leases (int, char *);
struct subnet *new_subnet PROTO ((char *));
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

/* socket.c */
u_int32_t *get_interface_list PROTO ((int *));
void listen_on PROTO ((u_int16_t, u_int32_t));
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
struct iaddr subnet_number (struct iaddr, struct iaddr);
struct iaddr ip_addr (struct iaddr, struct iaddr, unsigned long);
unsigned long host_addr (struct iaddr, struct iaddr);
int addr_eq (struct iaddr, struct iaddr);
char *piaddr (struct iaddr);
