/* confpars.c

   Parser for dhcpd config file... */

/*
 * Copyright (c) 1995, 1996, 1997, 1998 The Internet Software Consortium.
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
"$Id: confpars.c,v 1.53 1998/11/06 00:31:08 mellon Exp $ Copyright (c) 1995, 1996 The Internet Software Consortium.  All rights reserved.\n";
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
	enum dhcp_token token;
	int declaration = 0;

	new_parse (path_dhcpd_conf);

	/* Set up the initial dhcp option universe. */
	initialize_universes ();

	if ((cfile = fopen (path_dhcpd_conf, "r")) == NULL)
		error ("Can't open %s: %m", path_dhcpd_conf);
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
	enum dhcp_token token;

	new_parse (path_dhcpd_db);

	/* Open the lease file.   If we can't open it, fail.   The reason
	   for this is that although on initial startup, the absence of
	   a lease file is perfectly benign, if dhcpd has been running 
	   and this file is absent, it means that dhcpd tried and failed
	   to rewrite the lease database.   If we proceed and the
	   problem which caused the rewrite to fail has been fixed, but no
	   human has corrected the database problem, then we are left
	   thinking that no leases have been assigned to anybody, which
	   could create severe network chaos. */
	if ((cfile = fopen (path_dhcpd_db, "r")) == NULL)
		error ("Can't open lease database %s: %m -- %s",
		       path_dhcpd_db,
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
	       | GET_LEASE_HOSTNAMES boolean
	       | USE_HOST_DECL_NAME boolean
	       | NEXT_SERVER ip-addr-or-hostname SEMI
	       | option_parameter
	       | SERVER-IDENTIFIER ip-addr-or-hostname SEMI
	       | FILENAME string-parameter
	       | SERVER_NAME string-parameter
	       | hardware-parameter
	       | fixed-address-parameter
	       | ALLOW allow-deny-keyword
	       | DENY allow-deny-keyword
	       | USE_LEASE_ADDR_FOR_DEFAULT_ROUTE boolean

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
	enum dhcp_token token;
	char *val;
	struct shared_network *share;
	char *t, *n;
	struct expression *expr;
	struct data_string data;
	struct hardware hardware;
	struct executable_statement *et, *ep;
	struct option *option;
	struct option_cache *cache;
	int lose;

	switch (peek_token (&val, cfile)) {
	      case HOST:
		next_token (&val, cfile);
		if (type != HOST_DECL && type != CLASS_DECL)
			parse_host_declaration (cfile, group);
		else {
			parse_warn ("host declarations not allowed here.");
			skip_to_semi (cfile);
		}
		return 1;

	      case GROUP:
		next_token (&val, cfile);
		if (type != HOST_DECL && type != CLASS_DECL)
			parse_group_declaration (cfile, group);
		else {
			parse_warn ("host declarations not allowed here.");
			skip_to_semi (cfile);
		}
		return 1;

	      case TIMESTAMP:
		next_token (&val, cfile);
		parsed_time = parse_timestamp (cfile);
		break;

	      case SHARED_NETWORK:
		next_token (&val, cfile);
		if (type == SHARED_NET_DECL ||
		    type == HOST_DECL ||
		    type == SUBNET_DECL ||
		    type == CLASS_DECL) {
			parse_warn ("shared-network parameters not %s.",
				    "allowed here");
			skip_to_semi (cfile);
			break;
		}

		parse_shared_net_declaration (cfile, group);
		return 1;

	      case SUBNET:
		next_token (&val, cfile);
		if (type == HOST_DECL || type == SUBNET_DECL ||
		    type == CLASS_DECL) {
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
		next_token (&val, cfile);
		if (type == CLASS_DECL) {
			parse_warn ("class declarations not allowed here.");
			skip_to_semi (cfile);
			break;
		}
		parse_class_declaration (cfile, group, 0);
		return 1;

	      case USER_CLASS:
		next_token (&val, cfile);
		if (type == CLASS_DECL) {
			parse_warn ("class declarations not allowed here.");
			skip_to_semi (cfile);
			break;
		}
		parse_class_declaration (cfile, group, 1);
		return 1;

	      case CLASS:
		next_token (&val, cfile);
		if (type == CLASS_DECL) {
			parse_warn ("class declarations not allowed here.");
			skip_to_semi (cfile);
			break;
		}
		parse_class_declaration (cfile, group, 2);
		return 1;

	      case SUBCLASS:
		next_token (&val, cfile);
		if (type == CLASS_DECL) {
			parse_warn ("class declarations not allowed here.");
			skip_to_semi (cfile);
			break;
		}
		parse_class_declaration (cfile, group, 3);
		return 1;

	      case HARDWARE:
		next_token (&val, cfile);
		parse_hardware_param (cfile, &hardware);
		if (host_decl)
			host_decl -> interface = hardware;
		else
			parse_warn ("hardware address parameter %s",
				    "not allowed here.");
		break;

	      case FIXED_ADDR:
		next_token (&val, cfile);
		cache = (struct option_cache *)0;
		parse_fixed_addr_param (&cache, cfile);
		if (host_decl)
			host_decl -> fixed_addr = cache;
		else {
			parse_warn ("fixed-address parameter not %s",
				    "allowed here.");
			option_cache_dereference (&cache, "parse_statement");
		}
		break;

	      case RANGE:
		next_token (&val, cfile);
		if (type != SUBNET_DECL || !group -> subnet) {
			parse_warn ("range declaration not allowed here.");
			skip_to_semi (cfile);
			return declaration;
		}
		parse_address_range (cfile, group -> subnet);
		return declaration;

	      case ALLOW:
	      case DENY:
		token = next_token (&val, cfile);
		cache = (struct option_cache *)0;
		if (!parse_allow_deny (&cache, cfile,
				       token == ALLOW ? 1 : 0))
			return declaration;
		et = (struct executable_statement *)dmalloc (sizeof *et,
							     "allow/deny");
		if (!et)
			error ("no memory for %s statement",
			       token == ALLOW ? "allow" : "deny");
		memset (et, 0, sizeof *et);
		et -> op = supersede_option_statement;
		et -> data.option = cache;
		goto insert_statement;

	      case OPTION:
		token = next_token (&val, cfile);
		option = parse_option_name (cfile);
		if (option) {
			et = parse_option_statement
				(cfile, 1, option,
				 supersede_option_statement);
			if (!et)
				return declaration;
			goto insert_statement;
		} else
			return declaration;

		break;

	      default:
		et = (struct executable_statement *)0;
		if (is_identifier (token)) {
			option = ((struct option *)
				  hash_lookup (server_universe.hash,
					       (unsigned char *)val, 0));
			if (option) {
				token = next_token (&val, cfile);
				et = parse_option_statement
					(cfile, 1, option,
					 supersede_option_statement);
				if (!et)
					return declaration;
			}
		}

		if (!et) {
			lose = 0;
			et = parse_executable_statement (cfile, &lose);
			if (!et) {
				if (declaration && !lose)
					parse_warn ("expecting a %s.",
						    "declaration");
				else if (!lose)
					parse_warn ("expecting a parameter%s.",
						    " or declaration");
				skip_to_semi (cfile);
				return declaration;
			}
		}
		if (!et) {
			parse_warn ("expecting a %sdeclaration",
				    declaration ? "" :  "parameter or ");
			return declaration;
		}
	      insert_statement:
		if (group -> statements) {
			for (ep = group -> statements; ep -> next;
			     ep = ep -> next)
				;
			ep -> next = et;

		} else
			group -> statements = et;
		return declaration;
	}

	if (declaration) {
		parse_warn ("parameters not allowed after first declaration.");
		return 1;
	}

	return 0;
}

/* allow-deny-keyword :== BOOTP
   			| BOOTING
			| DYNAMIC_BOOTP
			| UNKNOWN_CLIENTS */

int parse_allow_deny (oc, cfile, flag)
	struct option_cache **oc;
	FILE *cfile;
	int flag;
{
	enum dhcp_token token;
	char *val;
	char rf = flag;
	struct expression *data = (struct expression *)0;
	int status;

	if (!make_const_data (&data, &rf, 1, 0, 1))
		return 0;

	token = next_token (&val, cfile);
	switch (token) {
	      case BOOTP:
		status = option_cache (oc, (struct data_string *)0, data,
				       &server_options [SV_ALLOW_BOOTP]);
		break;

	      case BOOTING:
		status = option_cache (oc, (struct data_string *)0, data,
				       &server_options [SV_ALLOW_BOOTING]);
		break;

	      case DYNAMIC_BOOTP:
		status = option_cache (oc, (struct data_string *)0, data,
				       &server_options [SV_DYNAMIC_BOOTP]);
		break;

	      case UNKNOWN_CLIENTS:
		status = (option_cache
			  (oc, (struct data_string *)0, data,
			   &server_options [SV_BOOT_UNKNOWN_CLIENTS]));
		break;

	      default:
		parse_warn ("expecting allow/deny key");
		skip_to_semi (cfile);
		return 0;
	}
	parse_semi (cfile);
	return status;
}

/* boolean :== ON SEMI | OFF SEMI | TRUE SEMI | FALSE SEMI */

int parse_boolean (cfile)
	FILE *cfile;
{
	enum dhcp_token token;
	char *val;
	int rv;

	token = next_token (&val, cfile);
	if (!strcasecmp (val, "true")
	    || !strcasecmp (val, "on"))
		rv = 1;
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

/* Expect a left brace; if there isn't one, skip over the rest of the
   statement and return zero; otherwise, return 1. */

int parse_lbrace (cfile)
	FILE *cfile;
{
	enum dhcp_token token;
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
	enum dhcp_token token;
	struct host_decl *host;
	char *name;
	int declaration = 0;

	token = peek_token (&val, cfile);
	if (token != LBRACE) {
		name = parse_host_name (cfile);
		if (!name)
			return;
	} else {
		name = (char *)0;
	}

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

	enter_host (host);
}

/* class-declaration :== STRING LBRACE parameters declarations RBRACE
*/

void parse_class_declaration (cfile, group, type)
	FILE *cfile;
	struct group *group;
	int type;
{
	char *val;
	enum dhcp_token token;
	struct class *class, *pc;
	int declaration = 0;
	int lose;
	struct data_string data;
	char *name;
	struct executable_statement *stmt = (struct executable_statement *)0;
	struct expression *expr;

	token = next_token (&val, cfile);
	if (token != STRING) {
		parse_warn ("Expecting class name");
		skip_to_semi (cfile);
		return;
	}

	/* See if there's already a class with the specified name. */
	pc = (struct class *)find_class (val);

	/* If this isn't a subclass, we're updating an existing class. */
	if (pc && type != 0 && type != 1 && type != 3) {
		class = pc;
		pc = (struct class *)0;
	}

	/* If this _is_ a subclass, there _must_ be a class with the
	   same name. */
	if (!pc && (type == 0 || type == 1 || type == 3)) {
		parse_warn ("no class named %s", val);
		skip_to_semi (cfile);
		return;
	}

	/* The old vendor-class and user-class declarations had an implicit
	   match.   We don't do the implicit match anymore.   Instead, for
	   backward compatibility, we have an implicit-vendor-class and an
	   implicit-user-class.   vendor-class and user-class declarations
	   are turned into subclasses of the implicit classes, and the
	   spawn expression of the implicit classes extracts the contents of
	   the vendor class or user class. */
	if (type == 0 || type == 1) {
		data.len = strlen (val);
		data.buffer = (struct buffer *)0;
		if (!buffer_allocate (&data.buffer,
				      data.len + 1, "parse_class_declaration"))
			error ("no memoy for class name.");
		data.data = &data.buffer -> data [0];
		data.terminated = 1;

		name = type ? "implicit-vendor-class" : "implicit-user-class";
	} else if (type == 2) {
		if (!(name = dmalloc (strlen (val) + 1,
				      "parse_class_declaration")))
			error ("No memory for class name %s.", val);
		strcpy (name, val);
	} else {
		name = (char *)0;
	}

	/* If this is a straight subclass, parse the hash string. */
	if (type == 3) {
		token = peek_token (&val, cfile);
		if (token == STRING) {
			token = next_token (&val, cfile);
			data.len = strlen (val);
			data.buffer = (struct buffer *)0;
			if (!buffer_allocate (&data.buffer, data.len + 1,
					     "parse_class_declaration"))
				return;
			data.terminated = 1;
			data.data = &data.buffer -> data [0];
			strcpy (data.data, val);
		} else if (token == NUMBER_OR_NAME || token == NUMBER) {
			memset (&data, 0, sizeof data);
			if (!parse_cshl (&data, cfile))
				return;
			data.terminated = 0;
			data.buffer = 0;
		}
	}

	/* See if there's already a class in the hash table matching the
	   hash data. */
	if (type == 0 || type == 1 || type == 3)
		class = ((struct class *)
			 hash_lookup (pc -> hash, data.data, data.len));

	/* If we didn't find an existing class, allocate a new one. */
	if (!class) {
		/* Allocate the class structure... */
		class = (struct class *)dmalloc (sizeof (struct class),
						 "parse_class_declaration");
		if (!class)
			error ("No memory for class %s.", val);
		memset (class, 0, sizeof *class);
		if (pc) {
			class -> group =
				clone_group (pc -> group,
					     "parse_class_declaration");
			add_hash (pc -> hash,
				  data.data, data.len, (unsigned char *)class);
		} else {
			class -> group =
				clone_group (group, "parse_class_declaration");
		}

		/* If this is an implicit vendor or user class, add a
		   statement that causes the vendor or user class ID to
		   be sent back in the reply. */
		if (type == 0 || type == 1) {
			stmt = ((struct executable_statement *)
				dmalloc (sizeof (struct executable_statement),
					 "implicit user/vendor class"));
			if (!stmt)
				error ("no memory for class statement.");
			memset (stmt, 0, sizeof *stmt);
			stmt -> op = supersede_option_statement;
			if (option_cache_allocate (&stmt -> data.option,
						   "parse_class_statement")) {
				stmt -> data.option -> data = data;
				stmt -> data.option -> option =
					dhcp_universe.options
					[type
					? DHO_DHCP_CLASS_IDENTIFIER
					: DHO_DHCP_USER_CLASS_ID];
			}
			class -> statements = stmt;
		}
	}

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
		} else if (token == MATCH) {
			if (pc) {
				parse_warn ("invalid match in subclass.");
				skip_to_semi (cfile);
				break;
			}
			if (class -> expr) {
				parse_warn ("can't override match.");
				skip_to_semi (cfile);
				break;
			}
			token = next_token (&val, cfile);
			token = next_token (&val, cfile);
			if (token != IF) {
				parse_warn ("expecting if after match");
				skip_to_semi (cfile);
				break;
			}
			parse_boolean_expression (&class -> expr, cfile,
						  &lose);
			if (lose)
				break;
#if defined (DEBUG_EXPRESSION_PARSE)
			print_expression ("class match", class -> expr);
#endif
		} else if (token == SPAWN) {
			if (pc) {
				parse_warn ("invalid spawn in subclass.");
				skip_to_semi (cfile);
				break;
			}
			if (class -> spawn) {
				parse_warn ("can't override spawn.");
				skip_to_semi (cfile);
				break;
			}
			token = next_token (&val, cfile);
			token = next_token (&val, cfile);
			if (token != WITH) {
				parse_warn ("expecting with after spawn");
				skip_to_semi (cfile);
				break;
			}
			parse_data_expression (&class -> spawn, cfile, &lose);
			if (lose)
				break;
#if defined (DEBUG_EXPRESSION_PARSE)
			print_expression ("class match", class -> spawn);
#endif
		} else {
			declaration = parse_statement (cfile, class -> group,
						       CLASS_DECL,
						       (struct host_decl *)0,
						       declaration);
		}
	} while (1);
}

/* shared-network-declaration :==
			hostname LBRACE declarations parameters RBRACE */

void parse_shared_net_declaration (cfile, group)
	FILE *cfile;
	struct group *group;
{
	char *val;
	enum dhcp_token token;
	struct shared_network *share;
	char *name;
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
	enum dhcp_token token;
	struct subnet *subnet, *t;
	struct iaddr iaddr;
	unsigned char addr [4];
	int len = sizeof addr;
	int declaration = 0;

	subnet = new_subnet ("parse_subnet_declaration");
	if (!subnet)
		error ("No memory for new subnet");
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

	/* Add the subnet to the list of subnets in this shared net. */
	if (!share -> subnets)
		share -> subnets = subnet;
	else {
		for (t = share -> subnets;
		     t -> next_sibling; t = t -> next_sibling)
			;
		t -> next_sibling = subnet;
	}
}

/* group-declaration :== RBRACE parameters declarations LBRACE */

void parse_group_declaration (cfile, group)
	FILE *cfile;
	struct group *group;
{
	char *val;
	enum dhcp_token token;
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

/* fixed-addr-parameter :== ip-addrs-or-hostnames SEMI
   ip-addrs-or-hostnames :== ip-addr-or-hostname
			   | ip-addrs-or-hostnames ip-addr-or-hostname */

int parse_fixed_addr_param (oc, cfile)
	struct option_cache **oc;
	FILE *cfile;
{
	char *val;
	enum dhcp_token token;
	struct expression *expr = (struct expression *)0;
	struct expression *tmp, *new;
	int status;

	do {
		tmp = (struct expression *)0;
		if (parse_ip_addr_or_hostname (&tmp, cfile, 1)) {
			if (expr) {
				new = (struct expression *)0;
				status = make_concat (&new, expr, tmp);
				expression_dereference
					(&expr, "parse_fixed_addr_param");
				expression_dereference
					(&tmp, "parse_fixed_addr_param");
				if (status)
					return 0;
				expr = new;
			} else
				expr = tmp;
		} else {
			if (expr)
				expression_dereference
					(&expr, "parse_fixed_addr_param");
			return 0;
		}
		token = peek_token (&val, cfile);
		if (token == COMMA)
			token = next_token (&val, cfile);
	} while (token == COMMA);

	if (!parse_semi (cfile)) {
		if (expr)
			expression_dereference (&expr,
						"parse_fixed_addr_param");
		return 0;
	}
	status = option_cache (oc, (struct data_string *)0, expr,
			       (struct option *)0);
	expression_dereference (&expr, "parse_fixed_addr_param");
	return status;
}

/* timestamp :== date

   Timestamps are actually not used in dhcpd.conf, which is a static file,
   but rather in the database file and the journal file.  (Okay, actually
   they're not even used there yet). */

TIME parse_timestamp (cfile)
	FILE *cfile;
{
	TIME rv;

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
		     | HOSTNAME hostname SEMI
		     | CLIENT_HOSTNAME hostname SEMI
		     | CLASS identifier SEMI
		     | DYNAMIC_BOOTP SEMI */

struct lease *parse_lease_declaration (cfile)
	FILE *cfile;
{
	char *val;
	enum dhcp_token token;
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
		strncpy (tbuf, val, sizeof tbuf);
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
					if (!lease.uid) {
						warn ("no space for uid");
						return (struct lease *)0;
					}
					memcpy (lease.uid, val, lease.uid_len);
				} else {
					lease.uid_len = 0;
					lease.uid = parse_numeric_aggregate
						(cfile, (unsigned char *)0,
						 &lease.uid_len, ':', 16, 8);
					if (!lease.uid) {
						warn ("no space for uid");
						return (struct lease *)0;
					}
					if (lease.uid_len == 0) {
						lease.uid = (unsigned char *)0;
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

			      case ABANDONED:
				seenbit = 256;
				lease.flags |= ABANDONED_LEASE;
				break;

			      case HOSTNAME:
				seenbit = 512;
				token = peek_token (&val, cfile);
				if (token == STRING)
					lease.hostname = parse_string (cfile);
				else
					lease.hostname =
						parse_host_name (cfile);
				if (!lease.hostname) {
					seenbit = 0;
					return (struct lease *)0;
				}
				break;

			      case CLIENT_HOSTNAME:
				seenbit = 1024;
				token = peek_token (&val, cfile);
				if (token == STRING)
					lease.client_hostname =
						parse_string (cfile);
				else
					lease.client_hostname =
						parse_host_name (cfile);
				break;

			      default:
				skip_to_semi (cfile);
				seenbit = 0;
				return (struct lease *)0;
			}

			if (token != HARDWARE && token != STRING) {
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
	enum dhcp_token token;
	char *val;
	int dynamic = 0;

	if ((token = peek_token (&val, cfile)) == DYNAMIC_BOOTP) {
		token = next_token (&val, cfile);
		dynamic = 1;
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

