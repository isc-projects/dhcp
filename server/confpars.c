/* confpars.c

   Parser for dhcpd config file... */

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

#ifndef lint
static char copyright[] =
"$Id: confpars.c,v 1.29 1996/08/29 20:12:37 mellon Exp $ Copyright (c) 1995, 1996 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include "dhctoken.h"

static TIME parsed_time;

/* conf-file :== parameters declarations EOF
   parameters :== <nil> | parameter | parameters parameter
   declarations :== <nil> | declaration | declarations declaration */

int readconf ()
{
	FILE *cfile;
	char *val;
	int token;
	int declaration = 0;

	new_parse (_PATH_DHCPD_CONF);

	/* Set up the initial dhcp option universe. */
	initialize_universes ();

	/* Set up the global defaults... */
	root_group.default_lease_time = 43200; /* 12 hours. */
	root_group.max_lease_time = 86400; /* 24 hours. */
	root_group.bootp_lease_cutoff = MAX_TIME;
	root_group.boot_unknown_clients = 1;

	if ((cfile = fopen (_PATH_DHCPD_CONF, "r")) == NULL)
		error ("Can't open %s: %m", _PATH_DHCPD_CONF);
	do {
		token = peek_token (&val, cfile);
		if (token == EOF)
			break;
		declaration = parse_statement (cfile, &root_group,
						 ROOT_GROUP,
						 (struct host_decl *)0,
						 declaration);
	} while (1);
	token = next_token (&val, cfile); /* Clear the peek buffer */

	return !warnings_occurred;
}

/* lease-file :== lease-declarations EOF
   lease-statments :== <nil>
   		     | lease-declaration
		     | lease-declarations lease-declaration */

void read_leases ()
{
	FILE *cfile;
	char *val;
	int token;
	jmp_buf bc;

	new_parse (_PATH_DHCPD_DB);

	/* Open the lease file.   If we can't open it, fail.   The reason
	   for this is that although on initial startup, the absence of
	   a lease file is perfectly benign, if dhcpd has been running 
	   and this file is absent, it means that dhcpd tried and failed
	   to rewrite the lease database.   If we proceed and the
	   problem which caused the rewrite to fail has been fixed, but no
	   human has corrected the database problem, then we are left
	   thinking that no leases have been assigned to anybody, which
	   could create severe network chaos. */
	if ((cfile = fopen (_PATH_DHCPD_DB, "r")) == NULL)
		error ("Can't open lease database %s: %m -- %s",
		       _PATH_DHCPD_DB,
		       "check for failed database rewrite attempt!");
	do {
		token = next_token (&val, cfile);
		if (token == EOF)
			break;
		if (token != LEASE) {
			warn ("Corrupt lease file - possible data loss!");
			skip_to_semi (cfile);
		} else {
			struct lease *lease;
			lease = parse_lease_declaration (cfile);
			if (lease)
				enter_lease (lease);
			else
				parse_warn ("possibly corrupt lease file");
		}

	} while (1);
}

/* statement :== parameter | declaration

   parameter :== timestamp
   	       | DEFAULT_LEASE_TIME lease_time
	       | MAX_LEASE_TIME lease_time
	       | DYNAMIC_BOOTP_LEASE_CUTOFF date
	       | DYNAMIC_BOOTP_LEASE_LENGTH lease_time
	       | BOOT_UNKNOWN_CLIENTS boolean
	       | ONE_LEASE_PER_CLIENT boolean
	       | NEXT_SERVER ip-addr-or-hostname SEMI
	       | option_parameter
	       | SERVER-IDENTIFIER ip-addr-or-hostname SEMI
	       | FILENAME string-parameter
	       | SERVER_NAME string-parameter
	       | hardware-parameter
	       | fixed-address-parameter

   declaration :== host-declaration
		 | group-declaration
		 | shared-network-declaration
		 | subnet-declaration
		 | VENDOR_CLASS class-declaration
		 | USER_CLASS class-declaration
		 | RANGE address-range-declaration */

int parse_statement (cfile, group, type, host_decl, declaration)
	FILE *cfile;
	struct group *group;
	int type;
	struct host_decl *host_decl;
	int declaration;
{
	int token;
	char *val;
	struct shared_network *share;
	struct subnet *subnet;
	char *t, *n;
	struct tree *tree;
	struct tree_cache *cache;
	struct hardware hardware;

	switch (next_token (&val, cfile)) {
	      case HOST:
		if (type != HOST_DECL)
			parse_host_declaration (cfile, group);
		else {
			parse_warn ("host declarations not allowed here.");
			skip_to_semi (cfile);
		}
		return 1;

	      case GROUP:
		if (type != HOST_DECL)
			parse_group_declaration (cfile, group);
		else {
			parse_warn ("host declarations not allowed here.");
			skip_to_semi (cfile);
		}
		return 1;

	      case TIMESTAMP:
		parsed_time = parse_timestamp (cfile);
		break;

	      case SHARED_NETWORK:
		if (type == SHARED_NET_DECL ||
		    type == HOST_DECL ||
		    type == SUBNET_DECL) {
			parse_warn ("shared-network parameters not %s.",
				    "allowed here");
			skip_to_semi (cfile);
			break;
		}

		parse_shared_net_declaration (cfile, group);
		return 1;

	      case SUBNET:
		if (type == HOST_DECL || type == SUBNET_DECL) {
			parse_warn ("subnet declarations not allowed here.");
			skip_to_semi (cfile);
			return 1;
		}

		/* If we're in a subnet declaration, just do the parse. */
		if (group -> shared_network) {
			parse_subnet_declaration (cfile,
						  group -> shared_network);
			break;
		}

		/* Otherwise, cons up a fake shared network structure
		   and populate it with the lone subnet... */

		share = new_shared_network ("parse_statement");
		if (!share)
			error ("No memory for shared subnet");
		share -> group = clone_group (group, "parse_statement:subnet");
		share -> group -> shared_network = share;

		parse_subnet_declaration (cfile, share);
		if (share -> subnets) {
			share -> interface =
				share -> subnets -> interface;

			n = piaddr (share -> subnets -> net);
			t = malloc (strlen (n) + 1);
			if (!t)
				error ("no memory for subnet name");
			strcpy (t, n);
			share -> name = t;
			enter_shared_network (share);
		}
		return 1;

	      case VENDOR_CLASS:
		parse_class_declaration (cfile, group, 0);
		return 1;

	      case USER_CLASS:
		parse_class_declaration (cfile, group, 1);
		return 1;

	      case DEFAULT_LEASE_TIME:
		parse_lease_time (cfile, &group -> default_lease_time);
		break;

	      case MAX_LEASE_TIME:
		parse_lease_time (cfile, &group -> max_lease_time);
		break;

	      case DYNAMIC_BOOTP_LEASE_CUTOFF:
		group -> bootp_lease_cutoff = parse_date (cfile);
		break;

	      case DYNAMIC_BOOTP_LEASE_LENGTH:
		parse_lease_time (cfile, &group -> bootp_lease_length);
		break;

	      case BOOT_UNKNOWN_CLIENTS:
		if (type == HOST_DECL)
			parse_warn ("boot-unknown-clients not allowed here.");
		group -> boot_unknown_clients = parse_boolean (cfile);
		break;

	      case ONE_LEASE_PER_CLIENT:
		if (type == HOST_DECL)
			parse_warn ("one-lease-per-client not allowed here.");
		group -> one_lease_per_client = parse_boolean (cfile);
		break;

	      case NEXT_SERVER:
		tree = parse_ip_addr_or_hostname (cfile, 0);
		if (!tree)
			break;
		cache = tree_cache (tree);
		if (!tree_evaluate (cache))
			error ("next-server is not known");
		group -> next_server.len = 4;
		memcpy (group -> next_server.iabuf,
			cache -> value, group -> next_server.len);
		parse_semi (cfile);
		break;
			
	      case OPTION:
		parse_option_param (cfile, group);
		break;

	      case SERVER_IDENTIFIER:
		if (type != ROOT_GROUP)
			parse_warn ("server-identifier only allowed at top %s",
				    "level.");
		tree = parse_ip_addr_or_hostname (cfile, 0);
		if (!tree)
			return declaration;
		cache = tree_cache (tree);
		if (type == ROOT_GROUP) {
			if (!tree_evaluate (cache))
				error ("server-identifier is not known");
			group -> next_server.len = 4;
			memcpy (server_identifier.iabuf,
				cache -> value, server_identifier.len);
		}
		token = next_token (&val, cfile);
		break;
			
	      case FILENAME:
		group -> filename = parse_string (cfile);
		break;

	      case SERVER_NAME:
		group -> server_name = parse_string (cfile);
		break;

	      case HARDWARE:
		parse_hardware_param (cfile, &hardware);
		if (host_decl)
			host_decl -> interface = hardware;
		else
			parse_warn ("hardware address parameter %s",
				    "not allowed here.");
		break;

	      case FIXED_ADDR:
		cache = parse_fixed_addr_param (cfile);
		if (host_decl)
			host_decl -> fixed_addr = cache;
		else
			parse_warn ("fixed-address parameter not %s",
				    "allowed here.");
		break;

	      case RANGE:
		if (type != SUBNET_DECL || !group -> subnet) {
			parse_warn ("range declaration not allowed here.");
			skip_to_semi (cfile);
			return declaration;
		}
		parse_address_range (cfile, group -> subnet);
		return declaration;

	      default:
		if (declaration)
			parse_warn ("expecting a declaration.");
		else
			parse_warn ("expecting a parameter or declaration.");
		skip_to_semi (cfile);
		return declaration;
	}

	if (declaration) {
		parse_warn ("parameters not allowed after first declaration.");
		return 1;
	}

	return 0;
}

/* Skip to the semicolon ending the current statement.   If we encounter
   braces, the matching closing brace terminates the statement.   If we
   encounter a right brace but haven't encountered a left brace, return
   leaving the brace in the token buffer for the caller.   If we see a
   semicolon and haven't seen a left brace, return.   This lets us skip
   over:

   	statement;
	statement foo bar { }
	statement foo bar { statement { } }
	statement}
 
	...et cetera. */

void skip_to_semi (cfile)
	FILE *cfile;
{
	int token;
	char *val;
	int brace_count = 0;

	do {
		token = peek_token (&val, cfile);
		if (token == RBRACE) {
			if (brace_count) {
				token = next_token (&val, cfile);
				if (!--brace_count)
					return;
			} else
				return;
		} else if (token == LBRACE) {
			brace_count++;
		} else if (token == SEMI && !brace_count) {
			token = next_token (&val, cfile);
			return;
		}
		token = next_token (&val, cfile);
	} while (token != EOF);
}

/* boolean :== ON SEMI | OFF SEMI | TRUE SEMI | FALSE SEMI */

int parse_boolean (cfile)
	FILE *cfile;
{
	int token;
	char *val;
	int rv;

	token = next_token (&val, cfile);
	if (!strcasecmp (val, "true")
	    || !strcasecmp (val, "on"))
		rv = 0;
	else if (!strcasecmp (val, "false")
		 || !strcasecmp (val, "off"))
		rv = 0;
	else {
		parse_warn ("boolean value (true/false/on/off) expected");
		skip_to_semi (cfile);
		return 0;
	}
	parse_semi (cfile);
	return rv;
}

int parse_semi (cfile)
	FILE *cfile;
{
	int token;
	char *val;

	token = next_token (&val, cfile);
	if (token != SEMI) {
		parse_warn ("semicolon expected.");
		skip_to_semi (cfile);
		return 0;
	}
	return 1;
}

/* Expect a left brace; if there isn't one, skip over the rest of the
   statement and return zero; otherwise, return 1. */

int parse_lbrace (cfile)
	FILE *cfile;
{
	int token;
	char *val;

	token = next_token (&val, cfile);
	if (token != LBRACE) {
		parse_warn ("expecting left brace.");
		skip_to_semi (cfile);
		return 0;
	}
	return 1;
}


/* host-declaration :== hostname RBRACE parameters declarations LBRACE */

void parse_host_declaration (cfile, group)
	FILE *cfile;
	struct group *group;
{
	char *val;
	int token;
	struct host_decl *host;
	char *name = parse_host_name (cfile);
	int declaration = 0;

	if (!name)
		return;

	host = (struct host_decl *)dmalloc (sizeof (struct host_decl),
					    "parse_host_declaration");
	if (!host)
		error ("can't allocate host decl struct %s.", name);

	host -> name = name;
	host -> group = clone_group (group, "parse_host_declaration");

	if (!parse_lbrace (cfile))
		return;

	do {
		token = peek_token (&val, cfile);
		if (token == RBRACE) {
			token = next_token (&val, cfile);
			break;
		}
		if (token == EOF) {
			token = next_token (&val, cfile);
			parse_warn ("unexpected end of file");
			break;
		}
		declaration = parse_statement (cfile, host -> group,
					       HOST_DECL, host,
					       declaration);
	} while (1);

	if (!host -> group -> options [DHO_HOST_NAME]) {
		host -> group -> options [DHO_HOST_NAME] =
			new_tree_cache ("parse_host_declaration");
		if (!host -> group -> options [DHO_HOST_NAME])
			error ("can't allocate a tree cache for hostname.");
		host -> group -> options [DHO_HOST_NAME] -> len =
			strlen (name);
		host -> group -> options [DHO_HOST_NAME] -> value =
			(unsigned char *)name;
		host -> group -> options [DHO_HOST_NAME] -> buf_size =
			host -> group -> options [DHO_HOST_NAME] -> len;
		host -> group -> options [DHO_HOST_NAME] -> timeout =
			0xFFFFFFFF;
		host -> group -> options [DHO_HOST_NAME] -> tree =
			(struct tree *)0;
	}

	enter_host (host);
}

/* hostname :== identifier | hostname DOT identifier */

char *parse_host_name (cfile)
	FILE *cfile;
{
	char *val;
	int token;
	int len = 0;
	char *s;
	char *t;
	pair c = (pair)0;
	
	/* Read a dotted hostname... */
	do {
		/* Read a token, which should be an identifier. */
		token = next_token (&val, cfile);
		if (!is_identifier (token) && token != NUMBER) {
			parse_warn ("expecting an identifier in hostname");
			skip_to_semi (cfile);
			return (char *)0;
		}
		/* Store this identifier... */
		if (!(s = (char *)malloc (strlen (val) + 1)))
			error ("can't allocate temp space for hostname.");
		strcpy (s, val);
		c = cons ((caddr_t)s, c);
		len += strlen (s) + 1;
		/* Look for a dot; if it's there, keep going, otherwise
		   we're done. */
		token = peek_token (&val, cfile);
		if (token == DOT)
			token = next_token (&val, cfile);
	} while (token == DOT);

	/* Assemble the hostname together into a string. */
	if (!(s = (char *)malloc (len)))
		error ("can't allocate space for hostname.");
	t = s + len;
	*--t = 0;
	while (c) {
		pair cdr = c -> cdr;
		int l = strlen ((char *)(c -> car));
		t -= l;
		memcpy (t, (char *)(c -> car), l);
		/* Free up temp space. */
		free (c -> car);
		free (c);
		c = cdr;
		if (t != s)
			*--t = '.';
	}
	return s;
}

/* class-declaration :== STRING LBRACE parameters declarations RBRACE
*/

void parse_class_declaration (cfile, group, type)
	FILE *cfile;
	struct group *group;
	int type;
{
	char *val;
	int token;
	struct class *class;
	int declaration;

	token = next_token (&val, cfile);
	if (token != STRING) {
		parse_warn ("Expecting class name");
		skip_to_semi (cfile);
		return;
	}

	class = add_class (type, val);
	if (!class)
		error ("No memory for class %s.", val);
	class -> group = clone_group (group, "parse_class_declaration");

	if (!parse_lbrace (cfile))
		return;

	do {
		token = peek_token (&val, cfile);
		if (token == RBRACE) {
			token = next_token (&val, cfile);
			break;
		} else if (token == EOF) {
			token = next_token (&val, cfile);
			parse_warn ("unexpected end of file");
			break;
		} else {
			declaration = parse_statement (cfile, class -> group,
						       CLASS_DECL,
						       (struct host_decl *)0,
						       declaration);
		}
	} while (1);
}

/* lease-time :== NUMBER SEMI */

void parse_lease_time (cfile, timep)
	FILE *cfile;
	TIME *timep;
{
	char *val;
	int token;

	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("Expecting numeric lease time");
		skip_to_semi (cfile);
		return;
	}
	convert_num ((unsigned char *)timep, val, 10, 32);
	/* Unswap the number - convert_num returns stuff in NBO. */
	*timep = ntohl (*timep); /* XXX */

	parse_semi (cfile);
}

/* shared-network-declaration :==
			hostname LBRACE declarations parameters RBRACE */

void parse_shared_net_declaration (cfile, group)
	FILE *cfile;
	struct group *group;
{
	char *val;
	int token;
	struct shared_network *share;
	struct subnet *first_net = (struct subnet *)0;
	struct subnet *last_net = (struct subnet *)0;
	struct subnet *next_net;
	char *name;
	struct tree_cache *server_next;
	int declaration = 0;

	share = new_shared_network ("parse_shared_net_declaration");
	if (!share)
		error ("No memory for shared subnet");
	share -> leases = (struct lease *)0;
	share -> last_lease = (struct lease *)0;
	share -> insertion_point = (struct lease *)0;
	share -> next = (struct shared_network *)0;
	share -> interface = (struct interface_info *)0;
	share -> group = clone_group (group, "parse_shared_net_declaration");
	share -> group -> shared_network = share;

	/* Get the name of the shared network... */
	token = peek_token (&val, cfile);
	if (token == STRING) {
		token = next_token (&val, cfile);

		if (val [0] == 0) {
			parse_warn ("zero-length shared network name");
			val = "<no-name-given>";
		}
		name = malloc (strlen (val) + 1);
		if (!name)
			error ("no memory for shared network name");
		strcpy (name, val);
	} else {
		name = parse_host_name (cfile);
		if (!name)
			return;
	}
	share -> name = name;

	if (!parse_lbrace (cfile))
		return;

	do {
		token = peek_token (&val, cfile);
		if (token == RBRACE) {
			token = next_token (&val, cfile);
			if (!share -> subnets) {
				parse_warn ("empty shared-network decl");
				return;
			}
			enter_shared_network (share);
			return;
		} else if (token == EOF) {
			token = next_token (&val, cfile);
			parse_warn ("unexpected end of file");
			break;
		}

		declaration = parse_statement (cfile, share -> group,
					       SHARED_NET_DECL,
					       (struct host_decl *)0,
					       declaration);
	} while (1);
}

/* subnet-declaration :==
	net NETMASK netmask RBRACE parameters declarations LBRACE */

void parse_subnet_declaration (cfile, share)
	FILE *cfile;
	struct shared_network *share;
{
	char *val;
	int token;
	struct subnet *subnet, *t;
	struct iaddr iaddr;
	unsigned char addr [4];
	int len = sizeof addr;
	int declaration = 0;

	subnet = new_subnet ("parse_subnet_declaration");
	if (!subnet)
		error ("No memory for new subnet");
	subnet -> next_subnet = subnet -> next_sibling = (struct subnet *)0;
	subnet -> shared_network = share;
	subnet -> group = clone_group (share -> group,
				       "parse_subnet_declaration");
	subnet -> group -> subnet = subnet;

	/* Get the network number... */
	if (!parse_numeric_aggregate (cfile, addr, &len, DOT, 10, 8))
		return;
	memcpy (iaddr.iabuf, addr, len);
	iaddr.len = len;
	subnet -> net = iaddr;

	token = next_token (&val, cfile);
	if (token != NETMASK) {
		parse_warn ("Expecting netmask");
		skip_to_semi (cfile);
		return;
	}

	/* Get the netmask... */
	if (!parse_numeric_aggregate (cfile, addr, &len, DOT, 10, 8))
		return;
	memcpy (iaddr.iabuf, addr, len);
	iaddr.len = len;
	subnet -> netmask = iaddr;

	enter_subnet (subnet);

	if (!parse_lbrace (cfile))
		return;

	do {
		token = peek_token (&val, cfile);
		if (token == RBRACE) {
			token = next_token (&val, cfile);
			break;
		} else if (token == EOF) {
			token = next_token (&val, cfile);
			parse_warn ("unexpected end of file");
			break;
		}
		declaration = parse_statement (cfile, subnet -> group,
					       SUBNET_DECL,
					       (struct host_decl *)0,
					       declaration);
	} while (1);

	/* If this subnet supports dynamic bootp, flag it so in the
	   shared_network containing it. */
	if (subnet -> group -> dynamic_bootp)
		share -> group -> dynamic_bootp = 1;
	if (subnet -> group -> one_lease_per_client)
		share -> group -> one_lease_per_client = 1;
	if (!share -> subnets)
		share -> subnets = subnet;
	else {
		for (t = share -> subnets;
		     t -> next_subnet;
		     t = t -> next_subnet)
			;
		t -> next_subnet = subnet;
	}
}

/* group-declaration :== RBRACE parameters declarations LBRACE */

void parse_group_declaration (cfile, group)
	FILE *cfile;
	struct group *group;
{
	char *val;
	int token;
	struct group *g;
	int declaration = 0;

	g = clone_group (group, "parse_group_declaration");

	if (!parse_lbrace (cfile))
		return;

	do {
		token = peek_token (&val, cfile);
		if (token == RBRACE) {
			token = next_token (&val, cfile);
			break;
		} else if (token == EOF) {
			token = next_token (&val, cfile);
			parse_warn ("unexpected end of file");
			break;
		}
		declaration = parse_statement (cfile, g, GROUP_DECL,
					       (struct host_decl *)0,
					       declaration);
	} while (1);
}

/* hardware-parameter :== HARDWARE ETHERNET csns SEMI
   csns :== NUMBER | csns COLON NUMBER */

void parse_hardware_param (cfile, hardware)
	FILE *cfile;
	struct hardware *hardware;
{
	char *val;
	int token;
	int hlen;
	unsigned char *t;

	token = next_token (&val, cfile);
	switch (token) {
	      case ETHERNET:
		hardware -> htype = ARPHRD_ETHER;
		break;
#ifdef ARPHRD_IEEE802 /* XXX */
	      case TOKEN_RING:
		hardware -> htype = ARPHRD_IEEE802;
		break;
#endif
	      default:
		parse_warn ("expecting a network hardware type");
		skip_to_semi (cfile);
		return;
	}

	/* Parse the hardware address information.   Technically,
	   it would make a lot of sense to restrict the length of the
	   data we'll accept here to the length of a particular hardware
	   address type.   Unfortunately, there are some broken clients
	   out there that put bogus data in the chaddr buffer, and we accept
	   that data in the lease file rather than simply failing on such
	   clients.   Yuck. */
	hlen = 0;
	t = parse_numeric_aggregate (cfile, (unsigned char *)0, &hlen,
				     COLON, 16, 8);
	if (!t)
		return;
	if (hlen > sizeof hardware -> haddr) {
		free (t);
		parse_warn ("hardware address too long");
	} else {
		hardware -> hlen = hlen;
		memcpy ((unsigned char *)&hardware -> haddr [0],
			t, hardware -> hlen);
		free (t);
	}
	
	token = next_token (&val, cfile);
	if (token != SEMI) {
		parse_warn ("expecting semicolon.");
		skip_to_semi (cfile);
	}
}

/* string-parameter :== STRING SEMI */

char *parse_string (cfile)
	FILE *cfile;
{
	char *val;
	int token;
	char *s;

	token = next_token (&val, cfile);
	if (token != STRING) {
		parse_warn ("filename must be a string");
		skip_to_semi (cfile);
		return (char *)0;
	}
	s = (char *)malloc (strlen (val) + 1);
	if (!s)
		error ("no memory for string %s.", val);
	strcpy (s, val);

	if (!parse_semi (cfile))
		return (char *)0;
	return s;
}

/* ip-addr-or-hostname :== ip-address | hostname
   ip-address :== NUMBER DOT NUMBER DOT NUMBER DOT NUMBER
   
   Parse an ip address or a hostname.   If uniform is zero, put in
   a TREE_LIMIT node to catch hostnames that evaluate to more than
   one IP address. */

struct tree *parse_ip_addr_or_hostname (cfile, uniform)
	FILE *cfile;
	int uniform;
{
	char *val;
	int token;
	unsigned char addr [4];
	int len = sizeof addr;
	char *name;
	struct tree *rv;

	token = peek_token (&val, cfile);
	if (is_identifier (token)) {
		name = parse_host_name (cfile);
		if (!name)
			return (struct tree *)0;
		rv = tree_host_lookup (name);
		if (!uniform)
			rv = tree_limit (rv, 4);
	} else if (token == NUMBER) {
		if (!parse_numeric_aggregate (cfile, addr, &len, DOT, 10, 8))
			return (struct tree *)0;
		rv = tree_const (addr, len);
	} else {
		if (token != RBRACE && token != LBRACE)
			token = next_token (&val, cfile);
		parse_warn ("%s (%d): expecting IP address or hostname",
			    val, token);
		if (token != SEMI)
			skip_to_semi (cfile);
		return (struct tree *)0;
	}

	return rv;
}	
	

/* fixed-addr-parameter :== ip-addrs-or-hostnames SEMI
   ip-addrs-or-hostnames :== ip-addr-or-hostname
			   | ip-addrs-or-hostnames ip-addr-or-hostname */

struct tree_cache *parse_fixed_addr_param (cfile)
	FILE *cfile;
{
	char *val;
	int token;
	struct tree *tree = (struct tree *)0;
	struct tree *tmp;

	do {
		tmp = parse_ip_addr_or_hostname (cfile, 0);
		if (tree)
			tree = tree_concat (tree, tmp);
		else
			tree = tmp;
		token = peek_token (&val, cfile);
		if (token == COMMA)
			token = next_token (&val, cfile);
	} while (token == COMMA);

	if (!parse_semi (cfile))
		return (struct tree_cache *)0;
	return tree_cache (tree);
}

/* option_parameter :== identifier DOT identifier <syntax> SEMI
		      | identifier <syntax> SEMI

   Option syntax is handled specially through format strings, so it
   would be painful to come up with BNF for it.   However, it always
   starts as above and ends in a SEMI. */

void parse_option_param (cfile, group)
	FILE *cfile;
	struct group *group;
{
	char *val;
	int token;
	unsigned char buf [4];
	char *vendor;
	char *fmt;
	struct universe *universe;
	struct option *option;
	struct tree *tree = (struct tree *)0;
	struct tree *t;

	token = next_token (&val, cfile);
	if (!is_identifier (token)) {
		parse_warn ("expecting identifier after option keyword.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return;
	}
	vendor = malloc (strlen (val) + 1);
	strcpy (vendor, val);
	token = peek_token (&val, cfile);
	if (token == DOT) {
		/* Go ahead and take the DOT token... */
		token = next_token (&val, cfile);

		/* The next token should be an identifier... */
		token = next_token (&val, cfile);
		if (!is_identifier (token)) {
			parse_warn ("expecting identifier after '.'");
			if (token != SEMI)
				skip_to_semi (cfile);
			return;
		}

		/* Look up the option name hash table for the specified
		   vendor. */
		universe = (struct universe *)hash_lookup (&universe_hash,
							   vendor, 0);
		/* If it's not there, we can't parse the rest of the
		   declaration. */
		if (!universe) {
			parse_warn ("no vendor named %s.", vendor);
			skip_to_semi (cfile);
			return;
		}
	} else {
		/* Use the default hash table, which contains all the
		   standard dhcp option names. */
		val = vendor;
		universe = &dhcp_universe;
	}

	/* Look up the actual option info... */
	option = (struct option *)hash_lookup (universe -> hash, val, 0);

	/* If we didn't get an option structure, it's an undefined option. */
	if (!option) {
		if (val == vendor)
			parse_warn ("no option named %s", val);
		else
			parse_warn ("no option named %s for vendor %s",
				    val, vendor);
		skip_to_semi (cfile);
		return;
	}

	/* Free the initial identifier token. */
	free (vendor);

	/* Parse the option data... */
	do {
		/* Set a flag if this is an array of a simple type (i.e.,
		   not an array of pairs of IP addresses, or something
		   like that. */
		int uniform = option -> format [1] == 'A';

		for (fmt = option -> format; *fmt; fmt++) {
			if (*fmt == 'A')
				break;
			switch (*fmt) {
			      case 'X':
				token = peek_token (&val, cfile);
				if (token == NUMBER_OR_NAME ||
				    token == NUMBER) {
					do {
						token = next_token
							(&val, cfile);
						if (token != NUMBER
						    && token != NUMBER_OR_NAME)
							goto need_number;
						convert_num (buf, val, 16, 8);
						tree = tree_concat
							(tree,
							 tree_const (buf, 1));
						token = peek_token
							(&val, cfile);
						if (token == COLON)
							token = next_token
								(&val, cfile);
					} while (token == COLON);
				} else if (token == STRING) {
					token = next_token (&val, cfile);
					tree = tree_concat
						(tree,
						 tree_const (val,
							     strlen (val)));
				} else {
					parse_warn ("expecting string %s.",
						    "or hexadecimal data");
					skip_to_semi (cfile);
					return;
				}
				break;
					
			      case 't': /* Text string... */
				token = next_token (&val, cfile);
				if (token != STRING
				    && !is_identifier (token)) {
					parse_warn ("expecting string.");
					if (token != SEMI)
						skip_to_semi (cfile);
					return;
				}
				tree = tree_concat (tree,
						    tree_const (val,
								strlen (val)));
				break;

			      case 'I': /* IP address or hostname. */
				t = parse_ip_addr_or_hostname (cfile, uniform);
				if (!t)
					return;
				tree = tree_concat (tree, t);
				break;

			      case 'L': /* Unsigned 32-bit integer... */
			      case 'l':	/* Signed 32-bit integer... */
				token = next_token (&val, cfile);
				if (token != NUMBER) {
				      need_number:
					parse_warn ("expecting number.");
					if (token != SEMI)
						skip_to_semi (cfile);
					return;
				}
				convert_num (buf, val, 0, 32);
				tree = tree_concat (tree, tree_const (buf, 4));
				break;
			      case 's':	/* Signed 16-bit integer. */
			      case 'S':	/* Unsigned 16-bit integer. */
				token = next_token (&val, cfile);
				if (token != NUMBER)
					goto need_number;
				convert_num (buf, val, 0, 16);
				tree = tree_concat (tree, tree_const (buf, 2));
				break;
			      case 'b':	/* Signed 8-bit integer. */
			      case 'B':	/* Unsigned 8-bit integer. */
				token = next_token (&val, cfile);
				if (token != NUMBER)
					goto need_number;
				convert_num (buf, val, 0, 8);
				tree = tree_concat (tree, tree_const (buf, 1));
				break;
			      case 'f': /* Boolean flag. */
				token = next_token (&val, cfile);
				if (!is_identifier (token)) {
					parse_warn ("expecting identifier.");
				      bad_flag:
					if (token != SEMI)
						skip_to_semi (cfile);
					return;
				}
				if (!strcasecmp (val, "true")
				    || !strcasecmp (val, "on"))
					buf [0] = 1;
				else if (!strcasecmp (val, "false")
					 || !strcasecmp (val, "off"))
					buf [0] = 0;
				else {
					parse_warn ("expecting boolean.");
					goto bad_flag;
				}
				tree = tree_concat (tree, tree_const (buf, 1));
				break;
			      default:
				warn ("Bad format %c in parse_option_param.",
				      *fmt);
				skip_to_semi (cfile);
				return;
			}
		}
		if (*fmt == 'A') {
			token = peek_token (&val, cfile);
			if (token == COMMA) {
				token = next_token (&val, cfile);
				continue;
			}
			break;
		}
	} while (*fmt == 'A');

	token = next_token (&val, cfile);
	if (token != SEMI) {
		parse_warn ("semicolon expected.");
		skip_to_semi (cfile);
		return;
	}
	group -> options [option -> code] = tree_cache (tree);
}

/* timestamp :== date

   Timestamps are actually not used in dhcpd.conf, which is a static file,
   but rather in the database file and the journal file.  (Okay, actually
   they're not even used there yet). */

TIME parse_timestamp (cfile)
	FILE *cfile;
{
	TIME rv;
	char *val;
	int token;

	rv = parse_date (cfile);
	return rv;
}
		
/* lease_declaration :== LEASE ip_address LBRACE lease_parameters RBRACE

   lease_parameters :== <nil>
		      | lease_parameter
		      | lease_parameters lease_parameter

   lease_parameter :== STARTS date
		     | ENDS date
		     | TIMESTAMP date
		     | HARDWARE hardware-parameter
		     | UID hex_numbers SEMI
		     | HOST hostname SEMI
		     | CLASS identifier SEMI
		     | DYNAMIC_BOOTP SEMI */

struct lease *parse_lease_declaration (cfile)
	FILE *cfile;
{
	char *val;
	int token;
	unsigned char addr [4];
	int len = sizeof addr;
	int seenmask = 0;
	int seenbit;
	char tbuf [32];
	static struct lease lease;

	/* Zap the lease structure... */
	memset (&lease, 0, sizeof lease);

	/* Get the address for which the lease has been issued. */
	if (!parse_numeric_aggregate (cfile, addr, &len, DOT, 10, 8))
		return (struct lease *)0;
	memcpy (lease.ip_addr.iabuf, addr, len);
	lease.ip_addr.len = len;

	if (!parse_lbrace (cfile))
		return (struct lease *)0;

	do {
		token = next_token (&val, cfile);
		if (token == RBRACE)
			break;
		else if (token == EOF) {
			parse_warn ("unexpected end of file");
			break;
		}
		strncpy (val, tbuf, sizeof tbuf);
		tbuf [(sizeof tbuf) - 1] = 0;

		/* Parse any of the times associated with the lease. */
		if (token == STARTS || token == ENDS || token == TIMESTAMP) {
			TIME t;
			t = parse_date (cfile);
			switch (token) {
			      case STARTS:
				seenbit = 1;
				lease.starts = t;
				break;
			
			      case ENDS:
				seenbit = 2;
				lease.ends = t;
				break;
				
			      case TIMESTAMP:
				seenbit = 4;
				lease.timestamp = t;
				break;

			      default:
				/*NOTREACHED*/
				seenbit = 0;
				break;
			}
		} else {
			switch (token) {
				/* Colon-seperated hexadecimal octets... */
			      case UID:
				seenbit = 8;
				token = peek_token (&val, cfile);
				if (token == STRING) {
					token = next_token (&val, cfile);
					lease.uid_len = strlen (val) + 1;
					lease.uid = (unsigned char *)
						malloc (lease.uid_len);
					memcpy (lease.uid, val, lease.uid_len);
				} else {
					lease.uid_len = 0;
					lease.uid = parse_numeric_aggregate
						(cfile, (unsigned char *)0,
						 &lease.uid_len, ':', 16, 8);
					if (!lease.uid)
						return (struct lease *)0;
					if (lease.uid_len == 0) {
						parse_warn ("zero-length uid");
						seenbit = 0;
						break;
					}
				}
				if (!lease.uid) {
					error ("No memory for lease uid");
				}
				break;

			      case CLASS:
				seenbit = 32;
				token = next_token (&val, cfile);
				if (!is_identifier (token)) {
					if (token != SEMI)
						skip_to_semi (cfile);
					return (struct lease *)0;
				}
				/* for now, we aren't using this. */
				break;

			      case HARDWARE:
				seenbit = 64;
				parse_hardware_param (cfile,
						     &lease.hardware_addr);
				break;

			      case DYNAMIC_BOOTP:
				seenbit = 128;
				lease.flags |= BOOTP_LEASE;
				break;

			      default:
				skip_to_semi (cfile);
				seenbit = 0;
				return (struct lease *)0;
			}

			if (token != HARDWARE) {
				token = next_token (&val, cfile);
				if (token != SEMI) {
					parse_warn ("semicolon expected.");
					skip_to_semi (cfile);
					return (struct lease *)0;
				}
			}
		}
		if (seenmask & seenbit) {
			parse_warn ("Too many %s parameters in lease %s\n",
				    tbuf, piaddr (lease.ip_addr));
		} else
			seenmask |= seenbit;

	} while (1);
	return &lease;
}

/* address-range-declaration :== ip-address ip-address SEMI
			       | DYNAMIC_BOOTP ip-address ip-address SEMI */

void parse_address_range (cfile, subnet)
	FILE *cfile;
	struct subnet *subnet;
{
	struct iaddr low, high;
	unsigned char addr [4];
	int len = sizeof addr;
	int token;
	char *val;
	int dynamic = 0;

	if ((token = peek_token (&val, cfile)) == DYNAMIC_BOOTP) {
		token = next_token (&val, cfile);
		if (subnet -> group -> boot_unknown_clients) {
			subnet -> group -> dynamic_bootp = dynamic = 1;
		} else {
			parse_warn ("dynamic-bootp conflicts with %s",
				    "boot_unknown_hosts 0");
		}
	}

	/* Get the bottom address in the range... */
	if (!parse_numeric_aggregate (cfile, addr, &len, DOT, 10, 8))
		return;
	memcpy (low.iabuf, addr, len);
	low.len = len;

	/* Only one address? */
	token = peek_token (&val, cfile);
	if (token == SEMI)
		high = low;
	else {
	/* Get the top address in the range... */
		if (!parse_numeric_aggregate (cfile, addr, &len, DOT, 10, 8))
			return;
		memcpy (high.iabuf, addr, len);
		high.len = len;
	}

	token = next_token (&val, cfile);
	if (token != SEMI) {
		parse_warn ("semicolon expected.");
		skip_to_semi (cfile);
		return;
	}

	/* Create the new address range... */
	new_address_range (low, high, subnet, dynamic);
}

/* date :== NUMBER NUMBER SLASH NUMBER SLASH NUMBER 
   		NUMBER COLON NUMBER COLON NUMBER SEMI

   Dates are always in GMT; first number is day of week; next is
   year/month/day; next is hours:minutes:seconds on a 24-hour
   clock. */

TIME parse_date (cfile)
	FILE *cfile;
{
	struct tm tm, *ap;
	int guess;
	char *val;
	int token;
	static int months [11] = { 31, 59, 90, 120, 151, 181,
					  212, 243, 273, 304, 334 };

	/* Day of week... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric day of week expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return (TIME)0;
	}
	tm.tm_wday = atoi (val);

	/* Year... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric year expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return (TIME)0;
	}
	tm.tm_year = atoi (val);
	if (tm.tm_year > 1900)
		tm.tm_year -= 1900;

	/* Slash seperating year from month... */
	token = next_token (&val, cfile);
	if (token != SLASH) {
		parse_warn ("expected slash seperating year from month.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return (TIME)0;
	}

	/* Month... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric month expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return (TIME)0;
	}
	tm.tm_mon = atoi (val) - 1;

	/* Slash seperating month from day... */
	token = next_token (&val, cfile);
	if (token != SLASH) {
		parse_warn ("expected slash seperating month from day.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return (TIME)0;
	}

	/* Month... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric day of month expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return (TIME)0;
	}
	tm.tm_mday = atoi (val);

	/* Hour... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric hour expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return (TIME)0;
	}
	tm.tm_hour = atoi (val);

	/* Colon seperating hour from minute... */
	token = next_token (&val, cfile);
	if (token != COLON) {
		parse_warn ("expected colon seperating hour from minute.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return (TIME)0;
	}

	/* Minute... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric minute expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return (TIME)0;
	}
	tm.tm_min = atoi (val);

	/* Colon seperating minute from second... */
	token = next_token (&val, cfile);
	if (token != COLON) {
		parse_warn ("expected colon seperating hour from minute.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return (TIME)0;
	}

	/* Minute... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric minute expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return (TIME)0;
	}
	tm.tm_sec = atoi (val);
	tm.tm_isdst = 0;

	/* XXX */ /* We assume that mktime does not use tm_yday. */
	tm.tm_yday = 0;

	/* Make sure the date ends in a semicolon... */
	token = next_token (&val, cfile);
	if (token != SEMI) {
		parse_warn ("semicolon expected.");
		skip_to_semi (cfile);
		return 0;
	}

	/* Guess the time value... */
	guess = ((((((365 * (tm.tm_year - 70) +	/* Days in years since '70 */
		      (tm.tm_year - 72) / 4 +	/* Leap days since '70 */
		      (tm.tm_mon		/* Days in months this year */
		       ? months [tm.tm_mon - 1]
		       : 0) +
		      (tm.tm_mon > 1 &&		/* Leap day this year */
		       ((tm.tm_year - 72) & 3)) +
		      tm.tm_mday) * 24) +	/* Day of month */
		    tm.tm_hour) * 60) +
		  tm.tm_min) * 60) + tm.tm_sec;

	/* This guess could be wrong because of leap seconds or other
	   weirdness we don't know about that the system does.   For
	   now, we're just going to accept the guess, but at some point
	   it might be nice to do a successive approximation here to
	   get an exact value.   Even if the error is small, if the
	   server is restarted frequently (and thus the lease database
	   is reread), the error could accumulate into something
	   significant. */

	return guess;
}

/* No BNF for numeric aggregates - that's defined by the caller.  What
   this function does is to parse a sequence of numbers seperated by
   the token specified in seperator.  If max is zero, any number of
   numbers will be parsed; otherwise, exactly max numbers are
   expected.  Base and size tell us how to internalize the numbers
   once they've been tokenized. */

unsigned char *parse_numeric_aggregate (cfile, buf,
					max, seperator, base, size)
	FILE *cfile;
	unsigned char *buf;
	int *max;
	int seperator;
	int base;
	int size;
{
	char *val;
	int token;
	unsigned char *bufp = buf, *s, *t;
	int count = 0;
	pair c = (pair)0;

	if (!bufp && *max) {
		bufp = (unsigned char *)malloc (*max * size / 8);
		if (!bufp)
			error ("can't allocate space for numeric aggregate");
	} else
		s = bufp;

	do {
		if (count) {
			token = peek_token (&val, cfile);
			if (token != seperator) {
				if (!*max)
					break;
				if (token != RBRACE && token != LBRACE)
					token = next_token (&val, cfile);
				parse_warn ("too few numbers.");
				if (token != SEMI)
					skip_to_semi (cfile);
				return (unsigned char *)0;
			}
			token = next_token (&val, cfile);
		}
		token = next_token (&val, cfile);

		if (token == EOF) {
			parse_warn ("unexpected end of file");
			break;
		}

		/* Allow NUMBER_OR_NAME if base is 16. */
		if (token != NUMBER &&
		    (base != 16 || token != NUMBER_OR_NAME)) {
			parse_warn ("expecting numeric value.");
			skip_to_semi (cfile);
			return (unsigned char *)0;
		}
		/* If we can, convert the number now; otherwise, build
		   a linked list of all the numbers. */
		if (s) {
			convert_num (s, val, base, size);
			s += size / 8;
		} else {
			t = (unsigned char *)malloc (strlen (val) + 1);
			if (!t)
				error ("no temp space for number.");
			strcpy (t, val);
			c = cons (t, c);
		}
	} while (++count != *max);

	/* If we had to cons up a list, convert it now. */
	if (c) {
		bufp = (unsigned char *)malloc (count * size / 8);
		if (!bufp)
			error ("can't allocate space for numeric aggregate.");
		s = bufp + count - size / 8;
		*max = count;
	}
	while (c) {
		pair cdr = c -> cdr;
		convert_num (s, (char *)(c -> car), base, size);
		s -= size / 8;
		/* Free up temp space. */
		free (c -> car);
		free (c);
		c = cdr;
	}
	return bufp;
}

void convert_num (buf, str, base, size)
	unsigned char *buf;
	char *str;
	int base;
	int size;
{
	char *ptr = str;
	int negative = 0;
	u_int32_t val = 0;
	int tval;
	int max;

	if (*ptr == '-') {
		negative = 1;
		++ptr;
	}

	/* If base wasn't specified, figure it out from the data. */
	if (!base) {
		if (ptr [0] == '0') {
			if (ptr [1] == 'x') {
				base = 16;
				ptr += 2;
			} else if (isascii (ptr [1]) && isdigit (ptr [1])) {
				base = 8;
				ptr += 1;
			} else {
				base = 10;
			}
		} else {
			base = 10;
		}
	}

	do {
		tval = *ptr++;
		/* XXX assumes ASCII... */
		if (tval >= 'a')
			tval = tval - 'a' + 10;
		else if (tval >= 'A')
			tval = tval - 'A' + 10;
		else if (tval >= '0')
			tval -= '0';
		else {
			warn ("Bogus number: %s.", str);
			break;
		}
		if (tval >= base) {
			warn ("Bogus number: %s: digit %d not in base %d\n",
			      str, tval, base);
			break;
		}
		val = val * base + tval;
	} while (*ptr);

	if (negative)
		max = (1 << (size - 1));
	else
		max = (1 << (size - 1)) + ((1 << (size - 1)) - 1);
	if (val > max) {
		switch (base) {
		      case 8:
			warn ("value %s%o exceeds max (%d) for precision.",
			      negative ? "-" : "", val, max);
			break;
		      case 16:
			warn ("value %s%x exceeds max (%d) for precision.",
			      negative ? "-" : "", val, max);
			break;
		      default:
			warn ("value %s%u exceeds max (%d) for precision.",
			      negative ? "-" : "", val, max);
			break;
		}
	}

	if (negative) {
		switch (size) {
		      case 8:
			*buf = -(unsigned long)val;
			break;
		      case 16:
			putShort (buf, -(unsigned long)val);
			break;
		      case 32:
			putLong (buf, -(unsigned long)val);
			break;
		      default:
			warn ("Unexpected integer size: %d\n", size);
			break;
		}
	} else {
		switch (size) {
		      case 8:
			*buf = (u_int8_t)val;
			break;
		      case 16:
			putUShort (buf, (u_int16_t)val);
			break;
		      case 32:
			putULong (buf, val);
			break;
		      default:
			warn ("Unexpected integer size: %d\n", size);
			break;
		}
	}
}
