/* confpars.c

   Parser for dhcpd config file... */

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

#ifndef lint
static char copyright[] =
"$Id: confpars.c,v 1.73.2.9 2000/07/01 04:50:37 mellon Exp $ Copyright (c) 1995, 1996 The Internet Software Consortium.  All rights reserved.\n";
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
	config_universe = &server_universe;

	root_group.authoritative = 0;

	if ((cfile = fopen (path_dhcpd_conf, "r")) == NULL)
		log_fatal ("Can't open %s: %m", path_dhcpd_conf);
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
	if ((cfile = fopen (path_dhcpd_db, "r")) == NULL) {
		log_error ("Can't open lease database %s: %m -- %s",
			   path_dhcpd_db,
			   "check for failed database rewrite attempt!");
		log_error ("Please read the dhcpd.leases manual page if you");
 		log_fatal ("don't know what to do about this.");
	}

	do {
		token = next_token (&val, cfile);
		if (token == EOF)
			break;
		if (token != LEASE) {
			log_error ("Corrupt lease file - possible data loss!");
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
	       | AUTHORITATIVE
	       | NOT AUTHORITATIVE
	       | AUTH_KEY key-id key-value

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
	struct data_string key_id;

	token = peek_token (&val, cfile);

	switch (token) {
	      case AUTH_KEY:
		memset (&key_id, 0, sizeof key_id);
		if (parse_auth_key (&key_id, cfile)) {
			if (type == HOST_DECL)
				data_string_copy (&host_decl -> auth_key_id,
						  &key_id, "parse_statement");
			data_string_forget (&key_id, "parse_statement");
		}
		break;
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
			log_fatal ("No memory for shared subnet");
		share -> group = clone_group (group, "parse_statement:subnet");
		share -> group -> shared_network = share;

		parse_subnet_declaration (cfile, share);

		/* share -> subnets is the subnet we just parsed. */
		if (share -> subnets) {
			share -> interface =
				share -> subnets -> interface;

			/* Make the shared network name from network number. */
			n = piaddr (share -> subnets -> net);
			t = dmalloc (strlen (n) + 1,
				     "parse_statement");
			if (!t)
				log_fatal ("no memory for subnet name");
			strcpy (t, n);
			share -> name = t;

			/* Copy the authoritative parameter from the subnet,
			   since there is no opportunity to declare it here. */
			share -> group -> authoritative =
				share -> subnets -> group -> authoritative;
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

	      case POOL:
		next_token (&val, cfile);
		if (type != SUBNET_DECL && type != SHARED_NET_DECL) {
			parse_warn ("pool declared outside of network");
		}
		if (type == POOL_DECL) {
			parse_warn ("pool declared within pool.");
		}
		parse_pool_statement (cfile, group, type);
		return declaration;

	      case RANGE:
		next_token (&val, cfile);
		if (type != SUBNET_DECL || !group -> subnet) {
			parse_warn ("range declaration not allowed here.");
			skip_to_semi (cfile);
			return declaration;
		}
		parse_address_range (cfile, group, type, (struct pool *)0);
		return declaration;

	      case TOKEN_NOT:
		token = next_token (&val, cfile);
		token = next_token (&val, cfile);
		switch (token) {
		      case AUTHORITATIVE:
			group -> authoritative = 0;
			goto authoritative;
		      default:
			parse_warn ("expecting assertion");
			skip_to_semi (cfile);
			break;
		}
		break;
	      case AUTHORITATIVE:
		token = next_token (&val, cfile);
		group -> authoritative = 1;
	      authoritative:
		if (type == HOST_DECL)
			parse_warn ("authority makes no sense here."); 
		parse_semi (cfile);
		break;

		/* "server-identifier" is a special hack, equivalent to
		   "option dhcp-server-identifier". */
	      case SERVER_IDENTIFIER:
		option = dhcp_universe.options [DHO_DHCP_SERVER_IDENTIFIER];
		token = next_token (&val, cfile);
		goto finish_option;

	      case OPTION:
		token = next_token (&val, cfile);
		token = peek_token (&val, cfile);
		if (token == SPACE) {
			if (type != ROOT_GROUP) {
				parse_warn ("option space definitions %s",
					    "may not be scoped.");
				skip_to_semi (cfile);
				break;
			}
			parse_option_space_decl (cfile);
			return declaration;
		}

		option = parse_option_name (cfile, 1);
		if (option) {
			token = peek_token (&val, cfile);
			if (token == CODE) {
				if (type != ROOT_GROUP) {
					parse_warn ("option definitions%s",
						    " may not be scoped.");
					skip_to_semi (cfile);
					free_option (option,
						     "parse_statement");
					break;
				}
				next_token (&val, cfile);
				if (!parse_option_code_definition (cfile,
								   option))
					free_option (option,
						     "parse_statement");
				return declaration;
			}

			/* If this wasn't an option code definition, don't
			   allow an unknown option. */
			if (option -> code == -1) {
				parse_warn ("unknown option %s.%s",
					    option -> universe -> name,
					    option -> name);
				skip_to_semi (cfile);
				free_option (option, "parse_statement");
				return declaration;
			}

		      finish_option:
			et = parse_option_statement
				(cfile, 1, option,
				 supersede_option_statement);
			if (!et)
				return declaration;
			goto insert_statement;
		} else
			return declaration;

		break;

#if defined (FAILOVER_PROTOCOL)
	      case FAILOVER:
		parse_failover_peer (cfile, group, type);
		break;
#endif

	      default:
		et = (struct executable_statement *)0;
		lose = 0;
		et = parse_executable_statement (cfile, &lose);
		if (!et) {
			if (!lose) {
				if (declaration)
					parse_warn ("expecting a declaration");
				else
					parse_warn ("expecting a parameter %s",
						    "or declaration.");
				skip_to_semi (cfile);
			}
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

#if defined (FAILOVER_PROTOCOL)
void parse_failover_peer (cfile, group, type)
	FILE *cfile;
	struct group *group;
	int type;
{
	enum dhcp_token token;
	char *val;
	struct failover_peer *peer;
	TIME *tp;
	char *name;

	if (type != SHARED_NET_DECL && type != ROOT_GROUP) {
		parse_warn ("failover peer statements not in shared-network%s",
			    " declaration or at top level.");
		skip_to_semi (cfile);
		return;
	}

	token = next_token (&val, cfile);
	if (token != PEER) {
		parse_warn ("expecting peer keyword");
		skip_to_semi (cfile);
		return;
	}

	token = next_token (&val, cfile);
	if (is_identifier (token) || token == STRING) {
		name = dmalloc (strlen (name) + 1, "peer name");
		if (!peer -> name)
			log_fatal ("no memory for peer name %s", name);
	} else {
		parse_warn ("expecting identifier or left brace");
		skip_to_semi (cfile);
		return;
	}

	/* See if there's a peer declaration by this name. */
	peer = find_failover_peer (name);

	token = next_token (&val, cfile);
	if (token == SEMI) {
		dfree (name, "peer name");
		if (type != SHARED_NET_DECL)
			parse_warn ("failover peer reference not %s",
				    "in shared-network declaration");
		else {
			if (!peer) {
				parse_warn ("reference to unknown%s%s",
					    " failover peer ", name);
				return;
			}
			group -> shared_network -> failover_peer =
				peer;
		}
		return;
	} else if (token == MY || token == PARTNER) {
		if (!peer) {
			parse_warn ("reference to unknown%s%s",
				    " failover peer ", name);
			return;
		}
		if ((token == MY
		     ? peer -> my_state
		     : peer -> partner_state) = parse_failover_state (cfile) ==
		    invalid_state)
			skip_to_semi (cfile);
		else
			parse_semi (cfile);
		return;
	} else if (token != LBRACE) {
		parse_warn ("expecting left brace");
		skip_to_semi (cfile);
	}

	/* Make sure this isn't a redeclaration. */
	if (peer) {
		parse_warn ("redeclaration of failover peer %s", name);
		skip_to_rbrace (cfile, 1);
		return;
	}

	peer = new_failover_peer ("parse_failover_peer");
	if (!peer)
		log_fatal ("no memory for %sfailover peer%s%s.",
		       name ? "" : "anonymous", name ? " " : "", name);

	/* Save the name. */
	peer -> name = name;

	do {
		token = next_token (&val, cfile);
		switch (token) {
		      case RBRACE:
			break;
		      case PRIMARY:
			peer -> i_am = primary;
			break;
		      case SECONDARY:
			peer -> i_am = secondary;
			break;
		      case IDENTIFIER:
			if (!parse_ip_addr_or_hostname (&peer -> address,
							cfile, 0)) {
				skip_to_rbrace (cfile, 1);
				return;
			}
			break;
		      case PORT:
			token = next_token (&val, cfile);
			if (token != NUMBER) {
				parse_warn ("expecting number");
				skip_to_rbrace (cfile, 1);
			}
			peer -> port = atoi (val);
			if (!parse_semi (cfile)) {
				skip_to_rbrace (cfile, 1);
				return;
			}
			break;
		      case MAX_TRANSMIT_IDLE:
			tp = &peer -> max_transmit_idle;
			goto parse_idle;
		      case MAX_RESPONSE_DELAY:
			tp = &peer -> max_transmit_idle;
		      parse_idle:
			token = next_token (&val, cfile);
			if (token != NUMBER) {
				parse_warn ("expecting number.");
				skip_to_rbrace (cfile, 1);
				return;
			}
			*tp = atoi (val);
		      default:
			parse_warn ("invalid statement in peer declaration");
			skip_to_rbrace (cfile, 1);
			return;
		}
	} while (token != RBRACE);
		
	if (type == SHARED_NET_DECL) {
		group -> shared_network -> failover_peer = peer;
	}
	enter_failover_peer (peer);
}

enum failover_state parse_failover_state (cfile)
	FILE *cfile;
{
	enum dhcp_token token;
	char *val;

	token = next_token (&val, cfile);
	switch (token) {
	      case PARTNER_DOWN:
		return partner_down;
	      case NORMAL:
		return normal;
	      case COMMUNICATIONS_INTERRUPTED:
		return communications_interrupted;
	      case POTENTIAL_CONFLICT:
		return potential_conflict;
	      case RECOVER:
		return recover;
	      default:
		parse_warn ("unknown failover state");
		break;
	}
	return invalid_state;
}
#endif /* defined (FAILOVER_PROTOCOL) */

void parse_pool_statement (cfile, group, type)
	FILE *cfile;
	struct group *group;
	int type;
{
	enum dhcp_token token;
	char *val;
	int done = 0;
	struct pool *pool, **p;
	struct permit *permit;
	struct permit **permit_head;
	int declaration = 0;

	pool = new_pool ("parse_pool_statement");
	if (!pool)
		log_fatal ("no memory for pool.");

	pool -> group = clone_group (group, "parse_pool_statement");

	if (!parse_lbrace (cfile))
		return;
	do {
		token = peek_token (&val, cfile);
		switch (token) {
		      case RANGE:
			next_token (&val, cfile);
			parse_address_range (cfile, group, type, pool);
			break;
		      case ALLOW:
			permit_head = &pool -> permit_list;
		      get_permit:
			permit = new_permit ("parse_pool_statement");
			if (!permit)
				log_fatal ("no memory for permit");
			next_token (&val, cfile);
			token = next_token (&val, cfile);
			switch (token) {
			      case UNKNOWN:
				permit -> type = permit_unknown_clients;
			      get_clients:
				if (next_token (&val, cfile) != CLIENTS) {
					parse_warn ("expecting \"clients\"");
					skip_to_semi (cfile);
					free_permit (permit,
						     "parse_pool_statement");
					continue;
				}
				break;
				
			      case KNOWN:
				permit -> type = permit_known_clients;
				goto get_clients;
				
			      case AUTHENTICATED:
				permit -> type = permit_authenticated_clients;
				goto get_clients;
				
			      case UNAUTHENTICATED:
				permit -> type =
					permit_unauthenticated_clients;
				goto get_clients;

			      case ALL:
				permit -> type = permit_all_clients;
				goto get_clients;
				break;
				
			      case DYNAMIC:
				permit -> type = permit_dynamic_bootp_clients;
				if (next_token (&val, cfile) != BOOTP) {
					parse_warn ("expecting \"bootp\"");
					skip_to_semi (cfile);
					free_permit (permit,
						     "parse_pool_statement");
					continue;
				}
				goto get_clients;
				
			      case MEMBERS:
				if (next_token (&val, cfile) != OF) {
					parse_warn ("expecting \"of\"");
					skip_to_semi (cfile);
					free_permit (permit,
						     "parse_pool_statement");
					continue;
				}
				if (next_token (&val, cfile) != STRING) {
					parse_warn ("expecting class name.");
					skip_to_semi (cfile);
					free_permit (permit,
						     "parse_pool_statement");
					continue;
				}
				permit -> type = permit_class;
				permit -> class = find_class (val);
				if (!permit -> class)
					parse_warn ("no such class: %s", val);
				break;

			      default:
				parse_warn ("expecting permit type.");
				skip_to_semi (cfile);
				break;
			}
			while (*permit_head)
				permit_head = &((*permit_head) -> next);
			*permit_head = permit;
			parse_semi (cfile);
			break;

		      case DENY:
			permit_head = &pool -> prohibit_list;
			goto get_permit;
			
		      case RBRACE:
			next_token (&val, cfile);
			done = 1;
			break;

		      default:
			declaration = parse_statement (cfile, pool -> group,
						       POOL_DECL,
						       (struct host_decl *)0,
						       declaration);
			break;
		}
	} while (!done);

	if (type == SUBNET_DECL)
		pool -> shared_network = group -> subnet -> shared_network;
	else
		pool -> shared_network = group -> shared_network;

	p = &pool -> shared_network -> pools;
	for (; *p; p = &((*p) -> next))
		;
	*p = pool;
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
		log_fatal ("can't allocate host decl struct %s.", name);

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

struct class *parse_class_declaration (cfile, group, type)
	FILE *cfile;
	struct group *group;
	int type;
{
	char *val;
	enum dhcp_token token;
	struct class *class = (struct class *)0, *pc;
	int declaration = 0;
	int lose = 0;
	struct data_string data;
	char *name;
	struct executable_statement *stmt = (struct executable_statement *)0;
	struct expression *expr;
	int new = 1;

	token = next_token (&val, cfile);
	if (token != STRING) {
		parse_warn ("Expecting class name");
		skip_to_semi (cfile);
		return (struct class *)0;
	}

	/* See if there's already a class with the specified name. */
	pc = (struct class *)find_class (val);

	/* If this isn't a subclass, we're updating an existing class. */
	if (pc && type != 0 && type != 1 && type != 3) {
		class = pc;
		new = 0;
		pc = (struct class *)0;
	}

	/* If this _is_ a subclass, there _must_ be a class with the
	   same name. */
	if (!pc && (type == 0 || type == 1 || type == 3)) {
		parse_warn ("no class named %s", val);
		skip_to_semi (cfile);
		return (struct class *)0;
	}

	/* The old vendor-class and user-class declarations had an implicit
	   match.   We don't do the implicit match anymore.   Instead, for
	   backward compatibility, we have an implicit-vendor-class and an
	   implicit-user-class.   vendor-class and user-class declarations
	   are turned into subclasses of the implicit classes, and the
	   submatch expression of the implicit classes extracts the contents of
	   the vendor class or user class. */
	if (type == 0 || type == 1) {
		data.len = strlen (val);
		data.buffer = (struct buffer *)0;
		if (!buffer_allocate (&data.buffer,
				      data.len + 1, "parse_class_declaration"))
			log_fatal ("no memoy for class name.");
		data.data = &data.buffer -> data [0];
		data.terminated = 1;

		name = type ? "implicit-vendor-class" : "implicit-user-class";
	} else if (type == 2) {
		if (!(name = dmalloc (strlen (val) + 1,
				      "parse_class_declaration")))
			log_fatal ("No memory for class name %s.", val);
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
				return (struct class *)0;
			data.terminated = 1;
			data.data = &data.buffer -> data [0];
			strcpy ((char *)data.data, val);
		} else if (token == NUMBER_OR_NAME || token == NUMBER) {
			memset (&data, 0, sizeof data);
			if (!parse_cshl (&data, cfile))
				return (struct class *)0;
		} else {
			parse_warn ("Expecting string or hex list.");
			return (struct class *)0;
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
			log_fatal ("No memory for class %s.", val);
		memset (class, 0, sizeof *class);
		if (pc) {
			class -> group = pc -> group;
			class -> superclass = pc;
			class -> lease_limit = pc -> lease_limit;
			if (class -> lease_limit) {
				class -> billed_leases =
					dmalloc (class -> lease_limit *
						 sizeof (struct lease *),
						 "parse_class_declaration");
				if (!class -> billed_leases)
					log_fatal ("no memory for billing");
				memset (class -> billed_leases, 0,
					(class -> lease_limit *
					 sizeof class -> billed_leases));
			}
			data_string_copy (&class -> hash_string, &data,
					  "parse_class_declaration");
			if (!pc -> hash)
				pc -> hash = new_hash ();
			add_hash (pc -> hash,
				  class -> hash_string.data,
				  class -> hash_string.len,
				  (unsigned char *)class);
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
				log_fatal ("no memory for class statement.");
			memset (stmt, 0, sizeof *stmt);
			stmt -> op = supersede_option_statement;
			if (option_cache_allocate (&stmt -> data.option,
						   "parse_class_statement")) {
				stmt -> data.option -> data = data;
				stmt -> data.option -> option =
					dhcp_universe.options
					[type
					? DHO_VENDOR_CLASS_IDENTIFIER
					: DHO_USER_CLASS];
			}
			class -> statements = stmt;
		}

		/* Save the name, if there is one. */
		class -> name = name;
	}

	if (type == 0 || type == 1 || type == 3)
		data_string_forget (&data, "parse_class_declaration");

	/* Spawned classes don't have their own settings. */
	if (class -> superclass) {
		token = peek_token (&val, cfile);
		if (token == SEMI) {
			next_token (&val, cfile);
			return class;
		}
		/* Give the subclass its own group. */
		class -> group = clone_group (class -> group,
					      "parse_class_declaration");
	}

	if (!parse_lbrace (cfile))
		return (struct class *)0;

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
			token = peek_token (&val, cfile);
			if (token != IF)
				goto submatch;
			token = next_token (&val, cfile);
			parse_boolean_expression (&class -> expr, cfile,
						  &lose);
			if (lose)
				break;
#if defined (DEBUG_EXPRESSION_PARSE)
			print_expression ("class match", class -> expr);
#endif
			parse_semi (cfile);
		} else if (token == SPAWN) {
			if (pc) {
				parse_warn ("invalid spawn in subclass.");
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
			class -> spawning = 1;
		      submatch:
			if (class -> submatch) {
				parse_warn ("can't override existing %s.",
					    "submatch/spawn");
				skip_to_semi (cfile);
				break;
			}
			parse_data_expression (&class -> submatch,
					       cfile, &lose);
			if (lose)
				break;
#if defined (DEBUG_EXPRESSION_PARSE)
			print_expression ("class submatch",
					  class -> submatch);
#endif
			parse_semi (cfile);
		} else if (token == LEASE) {
			next_token (&val, cfile);
			token = next_token (&val, cfile);
			if (token != LIMIT) {
				parse_warn ("expecting \"limit\"");
				if (token != SEMI)
					skip_to_semi (cfile);
				break;
			}
			token = next_token (&val, cfile);
			if (token != NUMBER) {
				parse_warn ("expecting a number");
				if (token != SEMI)
					skip_to_semi (cfile);
				break;
			}
			class -> lease_limit = atoi (val);
			class -> billed_leases =
				dmalloc (class -> lease_limit *
					 sizeof (struct lease *),
					 "parse_class_declaration");
			if (!class -> billed_leases)
				log_fatal ("no memory for billed leases.");
			memset (class -> billed_leases, 0,
				(class -> lease_limit *
				 sizeof class -> billed_leases));
			have_billing_classes = 1;
			parse_semi (cfile);
		} else {
			declaration = parse_statement (cfile, class -> group,
						       CLASS_DECL,
						       (struct host_decl *)0,
						       declaration);
		}
	} while (1);
	if (type == 2 && new) {
		if (!collections -> classes)
			collections -> classes = class;
		else {
			struct class *cp;
			for (cp = collections -> classes;
			     cp -> nic; cp = cp -> nic)
				;
			cp -> nic = class;
		}
	}
	return class;
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
		log_fatal ("No memory for shared subnet");
	share -> pools = (struct pool *)0;
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
		name = dmalloc (strlen (val) + 1,
				"parse_shared_net_declaration");
		if (!name)
			log_fatal ("no memory for shared network name");
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
	struct subnet *subnet, *t, *u;
	struct iaddr iaddr;
	unsigned char addr [4];
	int len = sizeof addr;
	int declaration = 0;

	subnet = new_subnet ("parse_subnet_declaration");
	if (!subnet)
		log_fatal ("No memory for new subnet");
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
		u = (struct subnet *)0;
		for (t = share -> subnets;
		     t -> next_sibling; t = t -> next_sibling) {
			if (subnet_inner_than (subnet, t, 0)) {
				if (u)
					u -> next_sibling = subnet;
				else
					share -> subnets = subnet;
				subnet -> next_sibling = t;
				return;
			}
			u = t;
		}
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
				if (!status)
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
		     | DDNS_FWD_NAME hostname
		     | DDNS_REV_NAME hostname
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
					   dmalloc (lease.uid_len,
						    "parse_lease_declaration");
					if (!lease.uid) {
						log_error ("no space for uid");
						return (struct lease *)0;
					}
					memcpy (lease.uid, val, lease.uid_len);
				} else {
					lease.uid_len = 0;
					lease.uid = parse_numeric_aggregate
						(cfile, (unsigned char *)0,
						 &lease.uid_len, ':', 16, 8);
					if (!lease.uid) {
						log_error ("no space for uid");
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
					log_fatal ("No memory for lease uid");
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

			      case BILLING:
				seenbit = 2048;
				token = next_token (&val, cfile);
				if (token == CLASS) {
					token = next_token (&val, cfile);
					if (token != STRING) {
						parse_warn
							("expecting string");
						if (token != SEMI)
							skip_to_semi (cfile);
						token = BILLING;
						break;
					}
					lease.billing_class = find_class (val);
					if (!lease.billing_class)
						parse_warn ("unknown class %s",
							    val);
					parse_semi (cfile);
				} else if (token == SUBCLASS) {
					lease.billing_class =
						parse_class_declaration
						(cfile, (struct group *)0, 3);
				} else {
					parse_warn ("expecting \"class\"");
					if (token != SEMI)
						skip_to_semi (cfile);
				}
				token = BILLING;
				break;

			      case DDNS_FWD_NAME:
				seenbit = 4096;
				token = peek_token (&val, cfile);
				if (token == STRING)
					lease.ddns_fwd_name =
						parse_string (cfile);
				else
					lease.ddns_fwd_name =
						parse_host_name (cfile);
				break;

			      case DDNS_REV_NAME:
				seenbit = 8192;
				token = peek_token (&val, cfile);
				if (token == STRING)
					lease.ddns_rev_name =
						parse_string (cfile);
				else
					lease.ddns_rev_name =
						parse_host_name (cfile);
				break;

			      default:
				skip_to_semi (cfile);
				seenbit = 0;
				return (struct lease *)0;
			}

			if (token != HARDWARE && token != STRING
			    && token != BILLING) {
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

void parse_address_range (cfile, group, type, pool)
	FILE *cfile;
	struct group *group;
	int type;
	struct pool *pool;
{
	struct iaddr low, high, net;
	unsigned char addr [4];
	int len = sizeof addr;
	enum dhcp_token token;
	char *val;
	int dynamic = 0;
	struct subnet *subnet;
	struct shared_network *share;
	struct pool *p;

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

	if (type == SUBNET_DECL) {
		subnet = group -> subnet;
		share = subnet -> shared_network;
	} else {
		share = group -> shared_network;
		for (subnet = share -> subnets;
		     subnet; subnet = subnet -> next_sibling) {
			net = subnet_number (low, subnet -> netmask);
			if (addr_eq (net, subnet -> net))
				break;
		}
		if (!subnet) {
			parse_warn ("address range not on network %s",
				    group -> shared_network -> name);
			log_error ("Be sure to place pool statement after %s",
				   "related subnet declarations.");
			return;
		}
	}

	if (!pool) {
		struct pool *last = (struct pool *)0;

		/* If we're permitting dynamic bootp for this range,
		   then look for a pool with an empty prohibit list and
		   a permit list with one entry that permits all clients */
		for (pool = share -> pools; pool; pool = pool -> next) {
			if ((!dynamic && !pool -> permit_list && 
			     pool -> prohibit_list &&
			     !pool -> prohibit_list -> next &&
			     (pool -> prohibit_list -> type ==
			      permit_dynamic_bootp_clients)) ||
			    (dynamic && !pool -> prohibit_list &&
			     pool -> permit_list &&
			     !pool -> permit_list -> next &&
			     (pool -> permit_list -> type ==
			      permit_all_clients))) {
				break;
			}
			last = pool;
		}

		/* If we didn't get a pool, make one. */
		if (!pool) {
			struct permit *p;
			pool = new_pool ("parse_address_range");
			if (!pool)
				log_fatal ("no memory for ad-hoc pool.");
			p = new_permit ("parse_address_range");
			if (!p)
				log_fatal ("no memory for ad-hoc permit.");
			/* Dynamic pools permit all clients.   Otherwise
			   we prohibit BOOTP clients. */
			if (dynamic) {
				p -> type = permit_all_clients;
				pool -> permit_list = p;
			} else {
				p -> type = permit_dynamic_bootp_clients;
				pool -> prohibit_list = p;
			}

			if (share -> pools)
				last -> next = pool;
			else
				share -> pools = pool;
			pool -> shared_network = share;
			pool -> group = clone_group (share -> group,
						     "parse_address_range");
		}
	}

	/* Create the new address range... */
	new_address_range (low, high, subnet, pool);
}

