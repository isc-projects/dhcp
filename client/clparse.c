/* clparse.c

   Parser for dhclient config and lease files... */

/*
 * Copyright (c) 1995, 1996, 1997 The Internet Software Consortium.
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
"$Id: clparse.c,v 1.1 1997/02/18 14:27:53 mellon Exp $ Copyright (c) 1995, 1996 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include "dhctoken.h"

static TIME parsed_time;

/* client-conf-file :== client-declarations EOF
   client-declarations :== <nil>
			 | client-declaration
			 | client-declarations client-declaration */

int read_client_conf ()
{
	FILE *cfile;
	char *val;
	int token;
	int declaration = 0;
	struct client_config *config;
	struct client_state *state;
	struct interface_info *ip;

	new_parse (path_dhclient_conf);

	/* Set up the initial dhcp option universe. */
	initialize_universes ();

	/* Initialize the top level client configuration. */
	memset (&top_level_config, 0, sizeof top_level_config);

	if ((cfile = fopen (path_dhclient_conf, "r")) == NULL)
		error ("Can't open %s: %m", path_dhclient_conf);
	do {
		token = peek_token (&val, cfile);
		if (token == EOF)
			break;
		parse_client_statement (cfile, (struct interface_info *)0,
					&top_level_config);
	} while (1);
	token = next_token (&val, cfile); /* Clear the peek buffer */

	/* Set up state and config structures for clients that don't
	   have per-interface configuration declarations. */
	config = (struct client_config *)0;
	for (ip = interfaces; ip; ip = ip -> next) {
		if (!ip -> client) {
			ip -> client = (struct client_state *)
				malloc (sizeof (struct client_state));
			if (!ip -> client)
				error ("no memory for client state.");
			memset (ip -> client, 0, sizeof *(ip -> client));
			if (!config) {
				config = (struct client_config *)
					malloc (sizeof (struct client_config));
				if (!config)
					error ("no memory for client config.");
				memcpy (config, &top_level_config,
					sizeof top_level_config);
			}
			ip -> client -> config = config;
		}
	}

	return !warnings_occurred;
}

/* lease-file :== client-lease-statements EOF
   client-lease-statements :== <nil>
		     | client-lease-statements client-lease-statement */

void read_client_leases ()
{
	FILE *cfile;
	char *val;
	int token;

	new_parse (path_dhclient_db);

	/* Open the lease file.   If we can't open it, just return -
	   we can safely trust the server to remember our state. */
	if ((cfile = fopen (path_dhclient_db, "r")) == NULL)
		return;
	do {
		token = next_token (&val, cfile);
		if (token == EOF)
			break;
		if (token != LEASE) {
			warn ("Corrupt lease file - possible data loss!");
			skip_to_semi (cfile);
			break;
		} else
			parse_client_lease_statement (cfile);

	} while (1);
}

/* client-declaration :== 
	HOSTNAME string |
	hardware-declaration |
	client-identifier-declaration |
	REQUEST option-list |
	REQUIRE option-list |
	TIMEOUT number |
	RETRY number |
	SELECT_TIMEOUT number |
	SCRIPT string |
	interface-declaration |
	client-lease-statement */

void parse_client_statement (cfile, ip, config)
	FILE *cfile;
	struct interface_info *ip;
	struct client_config *config;
{
	int token;
	char *val;
	char *t, *n;
	struct hardware hardware;

	switch (next_token (&val, cfile)) {
	      case HOSTNAME:
		config -> dns_hostname = parse_string (cfile);
		return;

	      case CLIENT_IDENTIFIER:
		config -> cid_len = parse_X (cfile,
					     &config -> client_identifier);
		break;

	      case HARDWARE:
		if (ip) {
			parse_hardware_param (cfile, &ip -> hw_address);
		} else {
			parse_warn ("hardware address parameter %s",
				    "not allowed here.");
			skip_to_semi (cfile);
		}
		return;

	      case REQUEST:
		config -> requested_option_count =
			parse_option_list (cfile, config -> requested_options);
		return;

	      case REQUIRE:
		memset (config -> required_options, 0,
			sizeof config -> required_options);
		parse_option_list (cfile, config -> required_options);
		return;

	      case TIMEOUT:
		parse_lease_time (cfile, &config -> timeout);
		return;

	      case RETRY:
		parse_lease_time (cfile, &config -> retry_interval);
		return;

	      case SELECT_TIMEOUT:
		parse_lease_time (cfile, &config -> select_interval);
		return;

	      case SCRIPT:
		config -> script_name = parse_string (cfile);
		return;

	      case INTERFACE:
		if (ip)
			parse_warn ("nested interface declaration.");
		parse_interface_declaration (cfile, config);
		return;

	      case LEASE:
		parse_client_lease_statement (cfile);
		return;

	      default:
		parse_warn ("expecting a statement.");
		skip_to_semi (cfile);
		break;
	}
	token = next_token (&val, cfile);
	if (token != SEMI) {
		parse_warn ("semicolon expected.");
		skip_to_semi (cfile);
	}
}

int parse_X (cfile, p)
	FILE *cfile;
	u_int8_t **p;
{
	int token;
	char *val;
	unsigned char buf [1024];
	int buflen;
	unsigned char *s;

	token = peek_token (&val, cfile);
	if (token == NUMBER_OR_NAME || token == NUMBER) {
		do {
			token = next_token (&val, cfile);
			if (token != NUMBER && token != NUMBER_OR_NAME) {
				parse_warn ("expecting hexadecimal constant.");
				skip_to_semi (cfile);
				*p = (u_int8_t *)0;
				return 0;
			}
			convert_num (&buf [buflen], val, 16, 8);
			if (buflen++ > sizeof buf) {
				parse_warn ("hexadecimal constant too long.");
				skip_to_semi (cfile);
				*p = (u_int8_t *)0;
				return 0;
			}
			token = peek_token (&val, cfile);
			if (token == COLON)
				token = next_token (&val, cfile);
		} while (token == COLON);
		val = buf;
	} else if (token == STRING) {
		token = next_token (&val, cfile);
		buflen = strlen (val) + 1;
	} else {
		parse_warn ("expecting string or hexadecimal data");
		skip_to_semi (cfile);
		*p = (u_int8_t *)0;
		return 0;
	}
	*p = malloc (buflen);
	if (!*p)
		error ("out of memory allocating client id.\n");
	memcpy (*p, val, buflen);
	return buflen;
}

/* option-list :== option_name |
   		   option_list COMMA option_name */

int parse_option_list (cfile, list)
	FILE *cfile;
	u_int8_t *list;
{
	int ix, i;
	int token;
	char *val;

	ix = 0;
	do {
		token = next_token (&val, cfile);
		if (!is_identifier (token)) {
			parse_warn ("expected option name.");
			skip_to_semi (cfile);
			return 0;
		}
		for (i = 0; i < 256; i++) {
			if (!strcasecmp (dhcp_options [i].name, val))
				break;
		}
		if (i == 256) {
			parse_warn ("%s: expected option name.");
			skip_to_semi (cfile);
			return 0;
		}
		list [ix++] = i;
		if (ix == 256) {
			parse_warn ("%s: too many options.", val);
			skip_to_semi (cfile);
			return 0;
		}
		token = next_token (&val, cfile);
	} while (token == COMMA);
	if (token != SEMI) {
		parse_warn ("expecting semicolon.");
		skip_to_semi (cfile);
		return 0;
	}
	return ix;
}

/* interface-declaration :==
   	INTERFACE string LBRACE client-declarations RBRACE */

void parse_interface_declaration (cfile, outer_config)
	FILE *cfile;
	struct client_config *outer_config;
{
	int token;
	char *val;

	struct interface_info dummy_interface, *ip;
	struct client_state dummy_state;
	struct client_config dummy_config;

	token = next_token (&val, cfile);
	if (token != STRING) {
		parse_warn ("expecting interface name (in quotes).");
		skip_to_semi (cfile);
		return;
	}

	/* Find the interface (if any) that matches the name. */
	for (ip = interfaces; ip; ip = ip -> next) {
		if (!strcmp (ip -> name, val))
			break;
	}

	/* If we didn't find an interface, put up a dummy interface so
	   that we have some place to parse the bogus data.   Otherwise,
	   allocate a client state and client config structure for the
	   interface. */
	if (!ip) {
		parse_warn ("interface %s not found.", val);
		ip = &dummy_interface;
		memset (ip, 0, sizeof dummy_interface);
		ip -> client = &dummy_state;
		memset (ip -> client, 0, sizeof dummy_state);
		ip -> client -> config = &dummy_config;
	} else {
		ip -> client = ((struct client_state *)
				malloc (sizeof (struct client_state)));
		if (!ip -> client)
			error ("no memory for state for %s\n", val);
		memset (ip -> client, 0, sizeof *(ip -> client));
		ip -> client -> config =
			((struct client_config *)
			 malloc (sizeof (struct client_config)));
		if (!ip -> client -> config)
			error ("no memory for config for %s\n", val);
		memset (ip -> client -> config, 0,
			sizeof *(ip -> client -> config));
	}
	memcpy (ip -> client -> config, outer_config, sizeof *outer_config);

	token = next_token (&val, cfile);
	if (token != LBRACE) {
		parse_warn ("expecting left brace.");
		skip_to_semi (cfile);
		return;
	}

	do {
		token = peek_token (&val, cfile);
		if (token == EOF) {
			parse_warn ("unterminated interface declaration.");
			return;
		}
		if (token == RBRACE)
			break;
		parse_client_statement (cfile, ip, ip -> client -> config);
	} while (1);
	token = next_token (&val, cfile);
}

/* client-lease-statement :==
	LEASE RBRACE client-lease-declarations LBRACE

	client-lease-declarations :==
		<nil> |
		client-lease-declaration |
		client-lease-declarations client-lease-declaration */


void parse_client_lease_statement (cfile)
	FILE *cfile;
{
	struct client_lease *lease, *lp, *pl;
	struct interface_info *ip;
	int token;
	char *val;

	token = next_token (&val, cfile);
	if (token != LBRACE) {
		parse_warn ("expecting left brace.");
		skip_to_semi (cfile);
		return;
	}

	lease = (struct client_lease *)malloc (sizeof (struct client_lease));
	if (!lease)
		error ("no memory for lease.\n");
	memset (lease, 0, sizeof *lease);

	ip = (struct interface_info *)0;

	do {
		token = peek_token (&val, cfile);
		if (token == EOF) {
			parse_warn ("unterminated lease declaration.");
			return;
		}
		if (token == RBRACE)
			break;
		parse_client_lease_declaration (cfile, lease, &ip);
	} while (1);
	token = next_token (&val, cfile);

	/* If the lease declaration didn't include an interface
	   declaration that we recognized, it's of no use to us. */
	if (!ip) {
		free_client_lease (lease);
		return;
	}

	/* The last lease in the lease file on a particular interface is
	   the active lease for that interface.    Of course, we don't know
	   what the last lease in the file is until we've parsed the whole
	   file, so at this point, we assume that the lease we just parsed
	   is the active lease for its interface.   If there's already
	   an active lease for the interface, and this lease is for the same
	   ip address, then we just toss the old active lease and replace
	   it with this one.   If this lease is for a different address,
	   then if the old active lease has expired, we dump it; if not,
	   we put it on the list of leases for this interface which are
	   still valid but no longer active. */
	if (ip -> client -> active) {
		if (ip -> client -> active -> expiry < cur_time)
			free_client_lease (ip -> client -> active);
		else if (ip -> client -> active -> address.len ==
			 lease -> address.len &&
			 !memcmp (ip -> client -> active -> address.iabuf,
				  lease -> address.iabuf,
				  lease -> address.len))
			free_client_lease (ip -> client -> active);
		else {
			ip -> client -> active -> next =
				ip -> client -> leases;
			ip -> client -> leases = ip -> client -> active;
		}
	}
	ip -> client -> active = lease;

	/* The current lease may supersede a lease that's not the
	   active lease but is still on the lease list, so scan the
	   lease list looking for a lease with the same address, and
	   if we find it, toss it. */
	pl = (struct client_lease *)0;
	for (lp = ip -> client -> leases; lp; lp = lp -> next) {
		if (lp -> address.len == lease -> address.len &&
		    !memcmp (lp -> address.iabuf, lease -> address.iabuf,
			     lease -> address.len)) {
			if (pl)
				pl -> next = lp -> next;
			else
				ip -> client -> leases = lp -> next;
			free_client_lease (lp);
			break;
		}
	}
	/* phew. */
}

/* client-lease-declaration :==
	INTERFACE string |
	FIXED_ADDR ip_address |
	FILENAME string |
	SERVER_NAME string |
	option-decl |
	RENEW time-decl |
	REBIND time-decl |
	EXPIRE time-decl */

void parse_client_lease_declaration (cfile, lease, ipp)
	FILE *cfile;
	struct client_lease *lease;
	struct interface_info **ipp;
{
	int token;
	char *val;
	char *t, *n;
	struct interface_info *ip;

	switch (next_token (&val, cfile)) {
	      case INTERFACE:
		token = next_token (&val, cfile);
		if (token != STRING) {
			parse_warn ("expecting interface name (in quotes).");
			skip_to_semi (cfile);
			break;
		}
		for (ip = interfaces; ip; ip = ip -> next) {
			if (!strcmp (ip -> name, val))
				break;
		}
		*ipp = ip;
		break;

	      case FIXED_ADDR:
		parse_ip_addr (cfile, &lease -> address);
		break;

	      case FILENAME:
		lease -> filename = parse_string (cfile);
		return;

	      case SERVER_NAME:
		lease -> server_name = parse_string (cfile);
		return;

	      case RENEW:
		lease -> renewal = parse_date (cfile);
		return;

	      case REBIND:
		lease -> rebind = parse_date (cfile);
		return;

	      case EXPIRE:
		lease -> expiry = parse_date (cfile);
		return;

	      case OPTION:
		parse_option_decl (cfile, lease -> options);
		return;

	      default:
		parse_warn ("expecting lease declaration.");
		skip_to_semi (cfile);
		break;
	}
	token = next_token (&val, cfile);
	if (token != SEMI) {
		parse_warn ("expecting semicolon.");
		skip_to_semi (cfile);
	}
}

void parse_ip_addr (cfile, addr)
	FILE *cfile;
	struct iaddr *addr;
{
	char *val;
	int token;

	addr -> len = 4;
	parse_numeric_aggregate (cfile, addr -> iabuf,
				 &addr -> len, DOT, 10, 8);
}	

void parse_option_decl (cfile, options)
	FILE *cfile;
	struct option_data *options;
{
	char *val;
	int token;
	unsigned char buf [4];
	char *vendor;
	char *fmt;
	struct universe *universe;
	struct option *option;
	struct iaddr ip_addr;
	char *dp;
	int len;

	token = next_token (&val, cfile);
	if (!is_identifier (token)) {
		parse_warn ("expecting identifier after option keyword.");
		if (token != SEMI)
			skip_to_semi (cfile);
		return;
	}
	vendor = malloc (strlen (val) + 1);
	if (!vendor)
		error ("no memory for vendor information.");
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
				options [option -> code].len =
					parse_X (cfile,
						 (&options
						  [option -> code].data));
				break;
					
			      case 't': /* Text string... */
				options [option -> code].data =
					parse_string (cfile);
				options [option -> code].len =
					strlen (options [option -> code].data);
				break;

			      case 'I': /* IP address. */
				parse_ip_addr (cfile, &ip_addr);
				len = ip_addr.len;
				dp = ip_addr.iabuf;

			      alloc:
				options [option -> code].data =	malloc (len);
				if (!options [option -> code].data)
					error ("no memory for option data.");
				memcpy (options [option -> code].data,
					dp, len);
				options [option -> code].len = len;
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
				len = 4;
				dp = buf;
				goto alloc;

			      case 's':	/* Signed 16-bit integer. */
			      case 'S':	/* Unsigned 16-bit integer. */
				token = next_token (&val, cfile);
				if (token != NUMBER)
					goto need_number;
				convert_num (buf, val, 0, 16);
				len = 2;
				dp = buf;
				goto alloc;

			      case 'b':	/* Signed 8-bit integer. */
			      case 'B':	/* Unsigned 8-bit integer. */
				token = next_token (&val, cfile);
				if (token != NUMBER)
					goto need_number;
				convert_num (buf, val, 0, 8);
				len = 1;
				dp = buf;
				goto alloc;

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
				len = 1;
				dp = buf;
				goto alloc;

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
}

