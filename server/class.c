/* class.c

   Handling for client classes. */

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
"$Id: class.c,v 1.12 1999/07/02 20:58:48 mellon Exp $ Copyright (c) 1998 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

struct collection default_collection = {
	(struct collection *)0,
	"default",
	(struct class *)0,
};

struct collection *collections = &default_collection;
struct executable_statement *default_classification_rules;

int have_billing_classes;

/* Build the default classification rule tree. */

void classification_setup ()
{
	struct executable_statement *rules;
	struct expression *me;

	/* check-collection "default" */
	me = (struct expression *)dmalloc (sizeof (struct expression),
					   "default check expression");
	if (!me)
		log_fatal ("Can't allocate default check expression");
	memset (me, 0, sizeof *me);
	me -> op = expr_check;
	me -> data.check = &default_collection;
	
	/* eval ... */
	rules = (struct executable_statement *)
		dmalloc (sizeof (struct executable_statement),
			 "add default collection check rule");
	if (!rules)
		log_fatal ("Can't allocate check of default collection");
	memset (rules, 0, sizeof *rules);
	rules -> op = eval_statement;
	rules -> data.eval = me;

	default_classification_rules = rules;
}

void classify_client (packet)
	struct packet *packet;
{
	execute_statements (packet, (struct lease *)0, packet -> options,
			    (struct option_state *)0,
			    default_classification_rules);
}

int check_collection (packet, lease, collection)
	struct packet *packet;
	struct lease *lease;
	struct collection *collection;
{
	struct class *class, *nc;
	struct data_string data;
	int matched = 0;
	int status;

	for (class = collection -> classes; class; class = class -> nic) {
#if defined (DEBUG_CLASS_MATCHING)
		log_info ("checking against class %s...", class -> name);
#endif
		memset (&data, 0, sizeof data);
		/* If a class is for billing, don't put the client in the
		   class if we've already billed it to a different class. */
		if (class -> submatch) {
			status = evaluate_data_expression (&data,
							   packet,
							   packet -> options,
							   lease,
							   class -> submatch);
			if (status) {
				if ((nc = ((struct class *)
					   hash_lookup (class -> hash,
							data.data,
							data.len)))) {
#if defined (DEBUG_CLASS_MATCHING)
					log_info ("matches subclass %s.",
					      print_hex_1 (data.len,
							   data.data, 60));
#endif
					data_string_forget
						(&data, "check_collection");
					classify (packet, nc);
					matched = 1;
					continue;
				}
				if (!class -> spawning)
					continue;
#if defined (DEBUG_CLASS_MATCHING)
				log_info ("spawning subclass %s.",
				      print_hex_1 (data.len, data.data, 60));
#endif
				nc = (struct class *)
					dmalloc (sizeof (struct class),
						 "class spawn");
				memset (nc, 0, sizeof *nc);
				nc -> group = class -> group;
				nc -> superclass = class;
				nc -> lease_limit = class -> lease_limit;
				nc -> dirty = 1;
				if (nc -> lease_limit) {
					nc -> billed_leases =
						(dmalloc
						 (nc -> lease_limit *
						  sizeof (struct lease *),
						  "check_collection"));
					if (!nc -> billed_leases) {
						log_error ("no memory for%s",
							   " billing");
						data_string_forget
							(&nc -> hash_string,
							 "check_collection");
						dfree (nc, "check_collection");
						continue;
					}
					memset (nc -> billed_leases, 0,
						(nc -> lease_limit *
						 sizeof nc -> billed_leases));
				}
				data_string_copy (&nc -> hash_string, &data,
						  "check_collection");
				data_string_forget (&data, "check_collection");
				if (!class -> hash)
					class -> hash = new_hash ();
				add_hash (class -> hash,
					  nc -> hash_string.data,
					  nc -> hash_string.len,
					  (unsigned char *)nc);
				classify (packet, nc);
			}
			data_string_forget (&data, "check_collection");
		}

		status = (evaluate_boolean_expression_result
			  (packet, packet -> options, lease, class -> expr));
		if (status) {
			matched = 1;
#if defined (DEBUG_CLASS_MATCHING)
			log_info ("matches class.");
#endif
			classify (packet, class);
		}
	}
	return matched;
}

void classify (packet, class)
	struct packet *packet;
	struct class *class;
{
	if (packet -> class_count < PACKET_MAX_CLASSES)
		packet -> classes [packet -> class_count++] = class;
	else
		log_error ("too many groups for %s",
		      print_hw_addr (packet -> raw -> htype,
				     packet -> raw -> hlen,
				     packet -> raw -> chaddr));
}

struct class *find_class (name)
	char *name;
{
	struct collection *lp;
	struct class *cp;

	for (lp = collections; lp; lp = lp -> next) {
		for (cp = lp -> classes; cp; cp = cp -> nic)
			if (cp -> name && !strcmp (name, cp -> name))
				return cp;
	}
	return (struct class *)0;
}

int unbill_class (lease, class)
	struct lease *lease;
	struct class *class;
{
	int i;

	for (i = 0; i < class -> lease_limit; i++)
		if (class -> billed_leases [i] == lease)
			break;
	if (i == class -> lease_limit) {
		log_error ("lease %s unbilled with no billing arrangement.",
		      piaddr (lease -> ip_addr));
		return 0;
	}
	lease -> billing_class = (struct class *)0;
	class -> billed_leases [i] = (struct lease *)0;
	class -> leases_consumed--;
	return 1;
}

int bill_class (lease, class)
	struct lease *lease;
	struct class *class;
{
	int i;

	if (class -> leases_consumed == class -> lease_limit)
		return 0;

	for (i = 0; i < class -> lease_limit; i++)
		if (!class -> billed_leases [i])
			break;

	if (i == class -> lease_limit) {
		log_error ("class billing consumption disagrees with leases.");
		return 0;
	}

	class -> billed_leases [i] = lease;
	lease -> billing_class = class;
	class -> leases_consumed++;
	return 1;
}
