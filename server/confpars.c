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
"@(#) Copyright (c) 1995, 1996 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include "dhctoken.h"

static TIME parsed_time;

/* conf-file :== statements
   declarations :== <nil> | declaration | declarations declaration */

void readconf ()
{
	FILE *cfile;
	char *val;
	int token;

	tlname = _PATH_DHCPD_CONF;
	tlpos = tline = 0;

	/* Set up the initial dhcp option universe. */
	initialize_universes ();

	if ((cfile = fopen (_PATH_DHCPD_CONF, "r")) == NULL)
		error ("Can't open %s: %m", _PATH_DHCPD_CONF);
	do {
		token = peek_token (&val, cfile);
		if (token == EOF)
			break;
		parse_statement (cfile);
	} while (1);
	token = next_token (&val, cfile);
}

void read_leases ()
{
	FILE *cfile;
	char *val;
	int token;
	jmp_buf bc;

	tlname = _PATH_DHCPD_DB;
	tlpos = tline = 0;

	/* Open the lease file... */
	if ((cfile = fopen (_PATH_DHCPD_DB, "r")) == NULL) {
		warn ("Can't open lease database %s: %m", _PATH_DHCPD_DB);
		return;
	}
	do {
		token = next_token (&val, cfile);
		if (token == EOF)
			break;
		if (token != LEASE) {
			warn ("Corrupt lease file - possible data loss!");
			skip_to_semi (cfile);
		} else {
			if (!setjmp (bc)) {
				struct lease *lease;
				lease = parse_lease_statement (cfile,
							       jref (bc));
				enter_lease (lease);
			} else {
				parse_warn ("possibly corrupt lease file");
			}
		}

	} while (1);
}

/* statement :== host_statement */

void parse_statement (cfile)
	FILE *cfile;
{
	int token;
	char *val;
	jmp_buf bc;

	switch (next_token (&val, cfile)) {
	      case HOST:
		if (!setjmp (bc)) {
			struct host_decl *hd =
				parse_host_statement (cfile, jref (bc));
			if (hd) {
				enter_host (hd);
			}
		}
		break;
	      case LEASE:
		if (!setjmp (bc)) {
			struct lease *lease =
				parse_lease_statement (cfile, jref (bc));
			enter_lease (lease);
		}
		break;
	      case TIMESTAMP:
		if (!setjmp (bc)) {
			parsed_time = parse_timestamp (cfile, jref (bc));
		}
		break;
	      case SHARED_NETWORK:
		if (!setjmp (bc)) {
			parse_shared_net_statement (cfile, jref (bc));
		}
		break;
	      case SUBNET:
		if (!setjmp (bc)) {
			struct shared_network *share;
			struct subnet *subnet;
			char *t, *n;

			share = new_shared_network ("parse_statement");
			if (!share)
				error ("No memory for shared subnet");
			share -> leases = (struct lease *)0;
			share -> last_lease = (struct lease *)0;
			share -> insertion_point = (struct lease *)0;
			share -> next = (struct shared_network *)0;
			share -> default_lease_time = default_lease_time;
			share -> max_lease_time = max_lease_time;
			memcpy (share -> options,
				global_options, sizeof global_options);

			subnet = parse_subnet_statement (cfile, jref (bc),
							 share);
			share -> subnets = subnet;
			share -> interface = (struct interface_info *)0;
			n = piaddr (subnet -> net);
			t = dmalloc (strlen (n) + 1, "parse_statement");
			if (!t)
				error ("no memory for subnet name");
			strcpy (t, n);
			share -> name = t;
			enter_shared_network (share);
			goto need_semi;
		}
		break;
	      case VENDOR_CLASS:
		if (!setjmp (bc)) {
			parse_class_statement (cfile, jref (bc), 0);
		}
		break;
	      case USER_CLASS:
		if (!setjmp (bc)) {
			parse_class_statement (cfile, jref (bc), 1);
		}
		break;

	      case DEFAULT_LEASE_TIME:
		if (!setjmp (bc)) {
			parse_lease_time (cfile, jref (bc),
					  &default_lease_time);
			goto need_semi;
		}
		break;

	      case MAX_LEASE_TIME:
		if (!setjmp (bc)) {
			parse_lease_time (cfile, jref (bc), &max_lease_time);
			goto need_semi;
		}
		break;

	      case OPTION:
		if (!setjmp (bc)) {
			parse_option_decl (cfile, jref (bc), global_options);
			goto need_semi;
		}
		break;

	      case SERVER_IDENTIFIER:
		if (!setjmp (bc)) {
			struct tree_cache *server_id =
				tree_cache (parse_ip_addr_or_hostname
					    (cfile, jref (bc), 0));
			if (!tree_evaluate (server_id))
				error ("server identifier is not known");
			if (server_id -> len > 4)
				warn ("server identifier evaluates to more %s",
				      "than one IP address");
			server_identifier.len = 4;
			memcpy (server_identifier.iabuf,
				server_id -> value, server_identifier.len);
			goto need_semi;
		}
		break;
			
	      default:
		parse_warn ("expecting a declaration.");
		skip_to_semi (cfile);
		break;
	}
	return;

      need_semi:
	token = next_token (&val, cfile);
	if (token != SEMI) {
		parse_warn ("semicolon expected");
		skip_to_semi (cfile);
	}
}

void skip_to_semi (cfile)
	FILE *cfile;
{
	int token;
	char *val;

	do {
		token = next_token (&val, cfile);
	} while (token != SEMI && token != EOF);
}

/* host_statement :== HOST hostname declarations SEMI
   host_declarations :== <nil> | host_declaration
			       | host_declarations host_declaration SEMI */

struct host_decl *parse_host_statement (cfile, bc)
	FILE *cfile;
	jbp_decl (bc);
{
	char *val;
	int token;
	struct host_decl tmp, *perm;

	memset (&tmp, 0, sizeof tmp);
	tmp.name = parse_host_name (cfile, bc);
	do {
		token = peek_token (&val, cfile);
		if (token == SEMI) {
			token = next_token (&val, cfile);
			break;
		}
		parse_host_decl (cfile, bc, &tmp);
	} while (1);
	perm = (struct host_decl *)malloc (sizeof (struct host_decl));
	if (!perm)
		error ("can't allocate host decl struct for %s.", tmp.name);
	*perm = tmp;
	return perm;
}

/* host_name :== identifier | host_name DOT identifier */

char *parse_host_name (cfile, bc)
	FILE *cfile;
	jbp_decl (bc);
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
		if (!is_identifier (token)) {
			parse_warn ("expecting an identifier in hostname");
			skip_to_semi (cfile);
			longjmp (jdref (bc), 1);
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

/* class_statement :== VENDOR_CLASS STRING class_declarations SEMI
   		     | USER_CLASS class_declarations SEMI
   class_declarations :== <nil> | option_declaration
			        | option_declarations option_declaration SEMI
*/

void parse_class_statement (cfile, bc, type)
	FILE *cfile;
	jbp_decl (bc);
	int type;
{
	char *val;
	int token;
	struct class *class;

	token = next_token (&val, cfile);
	if (token != STRING) {
		parse_warn ("Expecting class name");
		skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}

	class = add_class (type, val);
	if (!class)
		error ("No memory for new class");

	do {
		token = peek_token (&val, cfile);
		if (token == SEMI) {
			token = next_token (&val, cfile);
			break;
		} else {
			parse_class_decl (cfile, bc, class);
		}
	} while (1);
}

/* class_declaration :== filename_declaration
   		       | option_declaration
		       | DEFAULT_LEASE_TIME NUMBER
		       | MAX_LEASE_TIME NUMBER */

void parse_class_decl (cfile, bc, class)
	FILE *cfile;
	jbp_decl (bc);
	struct class *class;
{
	char *val;
	int token;

	token = next_token (&val, cfile);
	switch (token) {
	      case FILENAME:
		class -> filename = parse_filename_decl (cfile, bc);
		break;
	      case OPTION:
		parse_option_decl (cfile, bc, class -> options);
		break;
	      default:
		parse_warn ("expecting a dhcp option declaration.");
		skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
		break;
	}
}

/* lease_time :== NUMBER */

void parse_lease_time (cfile, bc, timep)
	FILE *cfile;
	jbp_decl (bc);
	TIME *timep;
{
	char *val;
	int token;

	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("Expecting numeric lease time");
		skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
	convert_num ((unsigned char *)timep, val, 10, 32);
	/* Unswap the number - convert_num returns stuff in NBO. */
	*timep = ntohl (*timep); /* XXX */
}

/* shared_network_statement :== SHARED_NETWORK subnet_statements SEMI
   subnet_statements :== subnet_statement |
   			 subnet_statements subnet_statement */

void parse_shared_net_statement (cfile, bc)
	FILE *cfile;
	jbp_decl (bc);
{
	char *val;
	int token;
	struct shared_network *share;
	struct subnet *first_net = (struct subnet *)0;
	struct subnet *last_net = (struct subnet *)0;
	struct subnet *next_net;
	char *name;

	share = new_shared_network ("parse_shared_net_statement");
	if (!share)
		error ("No memory for shared subnet");
	share -> leases = (struct lease *)0;
	share -> last_lease = (struct lease *)0;
	share -> insertion_point = (struct lease *)0;
	share -> next = (struct shared_network *)0;
	share -> default_lease_time = default_lease_time;
	share -> max_lease_time = max_lease_time;
	share -> interface = (struct interface_info *)0;
	memcpy (share -> options, global_options, sizeof global_options);

	/* Get the name of the shared network... */
	token = next_token (&val, cfile);
	if (!is_identifier (token) && token != STRING) {
		skip_to_semi (cfile);
		parse_warn ("expecting shared network name");
		longjmp (jdref (bc), 1);
	}
	if (val [0] == 0) {
		parse_warn ("zero-length shared network name");
		val = "<no-name-given>";
	}
	name = dmalloc (strlen (val) + 1, "parse_shared_net_statement");
	if (!name)
		error ("no memory for shared network name");
	strcpy (name, val);
	share -> name = name;

	do {
		token = next_token (&val, cfile);
		switch (token) {
		      case SEMI:
			if (!first_net) {
				parse_warn ("empty shared-network decl");
				return;
			}
			share -> subnets = first_net;
			enter_shared_network (share);
			return;

		      case SUBNET:
			next_net = parse_subnet_statement (cfile, bc, share);
			if (!first_net)
				first_net = next_net;
			if (last_net)
				last_net -> next_sibling = next_net;
			last_net = next_net;
			break;

		      case OPTION:
			parse_option_decl (cfile, bc, share -> options);
			break;

		      case DEFAULT_LEASE_TIME:
			parse_lease_time (cfile, bc,
					  &share -> default_lease_time);
			break;

		      case MAX_LEASE_TIME:
			parse_lease_time (cfile, bc,
					  &share -> max_lease_time);
			break;

		      default:
			parse_warn ("expecting subnet declaration");
			skip_to_semi (cfile);
			longjmp (jdref (bc), 1);
		}
	} while (1);
}

/* subnet_statement :== SUBNET net NETMASK netmask declarations
   host_declarations :== <nil> | host_declaration
			       | host_declarations host_declaration SEMI */

struct subnet *parse_subnet_statement (cfile, bc, share)
	FILE *cfile;
	jbp_decl (bc);
	struct shared_network *share;
{
	char *val;
	int token;
	struct subnet *subnet;
	struct iaddr net, netmask;
	unsigned char addr [4];
	int len = sizeof addr;

	subnet = new_subnet ("parse_subnet_statement");
	if (!subnet)
		error ("No memory for new subnet");
	subnet -> next_subnet = subnet -> next_sibling = (struct subnet *)0;
	subnet -> shared_network = share;
	subnet -> default_lease_time = share -> default_lease_time;
	subnet -> max_lease_time = share -> max_lease_time;
	memcpy (subnet -> options, share -> options, sizeof subnet -> options);

	/* Get the network number... */
	parse_numeric_aggregate (cfile, bc, addr, &len, DOT, 10, 8);
	memcpy (net.iabuf, addr, len);
	net.len = len;
	subnet -> net = net;

	token = next_token (&val, cfile);
	if (token != NETMASK) {
		parse_warn ("Expecting netmask");
		skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}

	/* Get the netmask... */
	parse_numeric_aggregate (cfile, bc, addr, &len, DOT, 10, 8);
	memcpy (netmask.iabuf, addr, len);
	netmask.len = len;
	subnet -> netmask = netmask;

	enter_subnet (subnet);

	do {
		token = peek_token (&val, cfile);
		if (token == SEMI || token == SUBNET)
			break;
		parse_subnet_decl (cfile, bc, subnet);
	} while (1);

	/* If this subnet supports dynamic bootp, flag it so in the
	   shared_network containing it. */
	if (subnet -> dynamic_bootp)
		share -> dynamic_bootp = 1;
	return subnet;
}

/* subnet_declaration :== hardware_declaration | filename_declaration
		        | fixed_addr_declaration | option_declaration */

void parse_subnet_decl (cfile, bc, decl)
	FILE *cfile;
	jbp_decl (bc);
	struct subnet *decl;
{
	char *val;
	int token;

	token = next_token (&val, cfile);
	switch (token) {
	      case RANGE:
		parse_address_range (cfile, bc, decl);
		break;

	      case OPTION:
		parse_option_decl (cfile, bc, decl -> options);
		break;

	      case DEFAULT_LEASE_TIME:
		parse_lease_time (cfile, bc,
				  &decl -> default_lease_time);
		break;
		
	      case MAX_LEASE_TIME:
		parse_lease_time (cfile, bc,
				  &decl -> max_lease_time);
		break;

	      default:
		parse_warn ("expecting a subnet declaration.");
		skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
		break;
	}
}

/* host_declaration :== hardware_declaration | filename_declaration
		      | fixed_addr_declaration | option_declaration
		      | max_lease_declaration | default_lease_declaration */

void parse_host_decl (cfile, bc, decl)
	FILE *cfile;
	jbp_decl (bc);
	struct host_decl *decl;
{
	char *val;
	int token;

	token = next_token (&val, cfile);
	switch (token) {
	      case HARDWARE:
		parse_hardware_decl (cfile, bc, decl);
		break;
	      case FILENAME:
		decl -> filename = parse_filename_decl (cfile, bc);
		break;
	      case SERVER_NAME:
		decl -> server_name = parse_servername_decl (cfile, bc);
		break;
	      case FIXED_ADDR:
		parse_fixed_addr_decl (cfile, bc, decl);
		break;
	      case OPTION:
		parse_option_decl (cfile, bc, decl -> options);
		break;
	      case DEFAULT_LEASE_TIME:
		parse_lease_time (cfile, bc,
				  &decl -> default_lease_time);
		break;
	      case MAX_LEASE_TIME:
		parse_lease_time (cfile, bc,
				  &decl -> max_lease_time);
		break;
	      case CIADDR:
		decl -> ciaddr =
			tree_cache (parse_ip_addr_or_hostname (cfile, bc, 0));
		break;
	      case YIADDR:
		decl -> yiaddr =
			tree_cache (parse_ip_addr_or_hostname (cfile, bc, 0));
		break;
	      case SIADDR:
		decl -> siaddr =
			tree_cache (parse_ip_addr_or_hostname (cfile, bc, 0));
		break;
	      case GIADDR:
		decl -> giaddr =
			tree_cache (parse_ip_addr_or_hostname (cfile, bc, 0));
		break;
	      default:
		parse_warn ("expecting a dhcp option declaration.");
		skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
		break;
	}
}

/* hardware_decl :== HARDWARE ETHERNET NUMBER COLON NUMBER COLON NUMBER COLON
   				       NUMBER COLON NUMBER COLON NUMBER */

void parse_hardware_decl (cfile, bc, decl)
	FILE *cfile;
	jbp_decl (bc);
	struct host_decl *decl;
{
	int token;
	struct hardware hw;

	hw = parse_hardware_addr (cfile, bc);

	/* Copy out the information... */
	decl -> interface.htype = hw.htype;
	decl -> interface.hlen = hw.hlen;
	memcpy (decl -> interface.haddr, &hw.haddr [0], hw.hlen);
}

struct hardware parse_hardware_addr (cfile, bc)
	FILE *cfile;
	jbp_decl (bc);
{
	char *val;
	int token;
	int hlen;
	struct hardware rv;

	token = next_token (&val, cfile);
	switch (token) {
	      case ETHERNET:
		rv.htype = ARPHRD_ETHER;
		hlen = 6;
		parse_numeric_aggregate (cfile, bc,
					 (unsigned char *)&rv.haddr [0], &hlen,
					 COLON, 16, 8);
		rv.hlen = hlen;
		break;
	      default:
		parse_warn ("expecting a network hardware type");
		skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
	return rv;
}

/* filename_decl :== FILENAME STRING */

char *parse_filename_decl (cfile, bc)
	FILE *cfile;
	jbp_decl (bc);
{
	char *val;
	int token;
	char *s;

	token = next_token (&val, cfile);
	if (token != STRING) {
		parse_warn ("filename must be a string");
		skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
	s = (char *)malloc (strlen (val) + 1);
	if (!s)
		error ("no memory for filename.");
	strcpy (s, val);
	return s;
}

/* servername_decl :== SERVER_NAME STRING */

char *parse_servername_decl (cfile, bc)
	FILE *cfile;
	jbp_decl (bc);
{
	char *val;
	int token;
	char *s;

	token = next_token (&val, cfile);
	if (token != STRING) {
		parse_warn ("server name must be a string");
		skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
	s = (char *)malloc (strlen (val) + 1);
	if (!s)
		error ("no memory for server name.");
	strcpy (s, val);
	return s;
}

/* ip_addr_or_hostname :== ip_address | hostname
   ip_address :== NUMBER DOT NUMBER DOT NUMBER DOT NUMBER
   
   Parse an ip address or a hostname.   If uniform is zero, put in
   a TREE_LIMIT node to catch hostnames that evaluate to more than
   one IP address. */

struct tree *parse_ip_addr_or_hostname (cfile, bc, uniform)
	FILE *cfile;
	jbp_decl (bc);
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
		name = parse_host_name (cfile, bc);
		rv = tree_host_lookup (name);
		if (!uniform)
			rv = tree_limit (rv, 4);
	} else if (token == NUMBER) {
		parse_numeric_aggregate (cfile, bc, addr, &len, DOT, 10, 8);
		rv = tree_const (addr, len);
	} else {
		parse_warn ("%s (%d): expecting IP address or hostname",
			    val, token);
		skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
	return rv;
}	
	

/* fixed_addr_clause :==
	FIXED_ADDR fixed_addr_decls

   fixed_addr_decls :== ip_addr_or_hostname |
   			fixed_addr_decls ip_addr_or_hostname */

void parse_fixed_addr_decl (cfile, bc, decl)
	FILE *cfile;
	jbp_decl (bc);
	struct host_decl *decl;
{
	char *val;
	int token;
	struct tree *tree = (struct tree *)0;
	struct tree *tmp;

	do {
		tmp = parse_ip_addr_or_hostname (cfile, bc, 0);
		if (tree)
			tree = tree_concat (tree, tmp);
		else
			tree = tmp;
		token = peek_token (&val, cfile);
		if (token == COMMA)
			token = next_token (&val, cfile);
	} while (token == COMMA);
	decl -> fixed_addr = tree_cache (tree);
}

/* option_declaration :== OPTION identifier DOT identifier <syntax> |
			  OPTION identifier <syntax>

   Option syntax is handled specially through format strings, so it
   would be painful to come up with BNF for it.   However, it always
   starts as above. */

void parse_option_decl (cfile, bc, options)
	FILE *cfile;
	jbp_decl (bc);
	struct tree_cache **options;
{
	char *val;
	int token;
	unsigned char buf [4];
	char *vendor;
	char *fmt;
	struct universe *universe;
	struct option *option;
	struct tree *tree = (struct tree *)0;

	token = next_token (&val, cfile);
	if (!is_identifier (token)) {
		parse_warn ("expecting identifier after option keyword.");
		if (token != SEMI)
			skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
	vendor = dmalloc (strlen (val) + 1, "parse_option_decl");
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
			longjmp (jdref (bc), 1);
		}

		/* Look up the option name hash table for the specified
		   vendor. */
		universe = (struct universe *)hash_lookup (&universe_hash,
							   vendor, 0);
		/* If it's not there, we can't parse the rest of the
		   statement. */
		if (!universe) {
			parse_warn ("no vendor named %s.", vendor);
			skip_to_semi (cfile);
			longjmp (jdref (bc), 1);
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
		longjmp (jdref (bc), 1);
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
				if (token == NUMBER_OR_ATOM ||
				    token == NUMBER) {
					do {
						token = next_token
							(&val, cfile);
						if (token != NUMBER
						    && token != NUMBER_OR_ATOM)
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
					longjmp (jdref (bc), 1);
				}
				break;
					
			      case 't': /* Text string... */
				token = next_token (&val, cfile);
				if (token != STRING
				    && !is_identifier (token)) {
					parse_warn ("expecting string.");
					if (token != SEMI)
						skip_to_semi (cfile);
					longjmp (jdref (bc), 1);
				}
				tree = tree_concat (tree,
						    tree_const (val,
								strlen (val)));
				break;

			      case 'I': /* IP address or hostname. */
				tree = tree_concat (tree,
						    parse_ip_addr_or_hostname
						    (cfile, bc, uniform));
				break;

			      case 'L': /* Unsigned 32-bit integer... */
			      case 'l':	/* Signed 32-bit integer... */
				token = next_token (&val, cfile);
				if (token != NUMBER) {
				      need_number:
					parse_warn ("expecting number.");
					if (token != SEMI)
						skip_to_semi (cfile);
					longjmp (jdref (bc), 1);
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
					longjmp (jdref (bc), 1);
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
				warn ("Bad format %c in parse_option_decl.",
				      *fmt);
				skip_to_semi (cfile);
				longjmp (jdref (bc), 1);
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

	options [option -> code] = tree_cache (tree);
}

/* timestamp :== TIMESTAMP date SEMI

   Timestamps are actually not used in dhcpd.conf, which is a static file,
   but rather in the database file and the journal file. */

TIME parse_timestamp (cfile, bc)
	FILE *cfile;
	jbp_decl (bc);
{
	TIME rv;
	char *val;
	int token;

	rv = parse_date (cfile, bc);
	token = next_token (&val, cfile);
	if (token != SEMI) {
		parse_warn ("semicolon expected");
		skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
	return rv;
}
		
/* lease_decl :== LEASE ip_address lease_modifiers SEMI
   lease_modifiers :== <nil>
   		|	lease_modifier
		|	lease_modifier lease_modifiers
   lease_modifier :==	STARTS date
   		|	ENDS date
		|	UID hex_numbers
		|	HOST identifier
		|	CLASS identifier
		|	TIMESTAMP number
		|	DYNAMIC_BOOTP */

struct lease *parse_lease_statement (cfile, bc)
	FILE *cfile;
	jbp_decl (bc);
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
	parse_numeric_aggregate (cfile, bc, addr, &len, DOT, 10, 8);
	memcpy (lease.ip_addr.iabuf, addr, len);
	lease.ip_addr.len = len;

	do {
		token = next_token (&val, cfile);
		if (token == SEMI)
			break;
		strncpy (val, tbuf, sizeof tbuf);
		tbuf [(sizeof tbuf) - 1] = 0;

		/* Parse any of the times associated with the lease. */
		if (token == STARTS || token == ENDS || token == TIMESTAMP) {
			TIME t;
			t = parse_date (cfile, bc);
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
						(cfile, bc, (unsigned char *)0,
						 &lease.uid_len, ':', 16, 8);
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

#if 0
			      case HOST:
				seenbit = 16;
				token = next_token (&val, cfile);
				if (!is_identifier (token)) {
					if (token != SEMI)
						skip_to_semi (cfile);
					longjmp (jdref (bc), 1);
				}
				lease.host =
					find_host_by_name (val);
				if (!lease.host)
					parse_warn ("lease host ``%s'' is %s",
						    val,
						    "no longer known.");
				break;
#endif
					
			      case CLASS:
				seenbit = 32;
				token = next_token (&val, cfile);
				if (!is_identifier (token)) {
					if (token != SEMI)
						skip_to_semi (cfile);
					longjmp (jdref (bc), 1);
				}
				/* for now, we aren't using this. */
				break;

			      case HARDWARE:
				seenbit = 64;
				lease.hardware_addr
					= parse_hardware_addr (cfile, bc);
				break;

			      case DYNAMIC_BOOTP:
				seenbit = 128;
				lease.flags |= BOOTP_LEASE;
				break;

			      default:
				if (token != SEMI)
					skip_to_semi (cfile);
				longjmp (jdref (bc), 1);
				/*NOTREACHED*/
				seenbit = 0;
			}
		}
		if (seenmask & seenbit) {
			parse_warn ("Too many %s declarations in lease %s\n",
				    tbuf, piaddr (lease.ip_addr));
		} else
			seenmask |= seenbit;
	} while (1);
	return &lease;
}

/* address_range :== RANGE ip_address ip_address |
		     RANGE dynamic_bootp_statement ip_address ip_address */

void parse_address_range (cfile, bc, subnet)
	FILE *cfile;
	jbp_decl (bc);
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
		subnet -> dynamic_bootp = dynamic = 1;
	}

	/* Get the bottom address in the range... */
	parse_numeric_aggregate (cfile, bc, addr, &len, DOT, 10, 8);
	memcpy (low.iabuf, addr, len);
	low.len = len;

	/* Get the top address in the range... */
	parse_numeric_aggregate (cfile, bc, addr, &len, DOT, 10, 8);
	memcpy (high.iabuf, addr, len);
	high.len = len;

	/* Create the new address range... */
	new_address_range (low, high, subnet, dynamic);
}

/* date :== NUMBER NUMBER/NUMBER/NUMBER NUMBER:NUMBER:NUMBER

   Dates are always in GMT; first number is day of week; next is
   year/month/day; next is hours:minutes:seconds on a 24-hour
   clock. */

TIME parse_date (cfile, bc)
	FILE *cfile;
	jbp_decl (bc);
{
	struct tm tm;
	char *val;
	int token;

	/* Day of week... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric day of week expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
	tm.tm_wday = atoi (val);

	/* Year... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric year expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
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
		longjmp (jdref (bc), 1);
	}

	/* Month... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric month expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
	tm.tm_mon = atoi (val) - 1;

	/* Slash seperating month from day... */
	token = next_token (&val, cfile);
	if (token != SLASH) {
		parse_warn ("expected slash seperating month from day.");
		if (token != SEMI)
			skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}

	/* Month... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric day of month expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
	tm.tm_mday = atoi (val);

	/* Hour... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric hour expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
	tm.tm_hour = atoi (val);

	/* Colon seperating hour from minute... */
	token = next_token (&val, cfile);
	if (token != COLON) {
		parse_warn ("expected colon seperating hour from minute.");
		if (token != SEMI)
			skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}

	/* Minute... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric minute expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
	tm.tm_min = atoi (val);

	/* Colon seperating minute from second... */
	token = next_token (&val, cfile);
	if (token != COLON) {
		parse_warn ("expected colon seperating hour from minute.");
		if (token != SEMI)
			skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}

	/* Minute... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric minute expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
	tm.tm_sec = atoi (val);
	tm.tm_isdst = 0;

	/* XXX */ /* We assume that mktime does not use tm_yday. */
	tm.tm_yday = 0;

	return mktime (&tm);
}

/* No BNF for numeric aggregates - that's defined by the caller.  What
   this function does is to parse a sequence of numbers seperated by
   the token specified in seperator.  If max is zero, any number of
   numbers will be parsed; otherwise, exactly max numbers are
   expected.  Base and size tell us how to internalize the numbers
   once they've been tokenized. */

unsigned char *parse_numeric_aggregate (cfile, bc, buf,
					max, seperator, base, size)
	FILE *cfile;
	jbp_decl (bc);
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
				parse_warn ("too few numbers.");
				skip_to_semi (cfile);
				longjmp (jdref (bc), 1);
			}
			token = next_token (&val, cfile);
		}
		token = next_token (&val, cfile);
		/* Allow NUMBER_OR_ATOM if base is 16. */
		if (token != NUMBER &&
		    (base != 16 || token != NUMBER_OR_ATOM)) {
			parse_warn ("expecting numeric value.");
			skip_to_semi (cfile);
			longjmp (jdref (bc), 1);
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
