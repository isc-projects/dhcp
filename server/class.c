/* class.c

   Handling for client classes. */

/*
 * Copyright (c) 1998 The Internet Software Consortium.
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
"$Id: class.c,v 1.4 1998/11/06 00:16:22 mellon Exp $ Copyright (c) 1998 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

/*
 * Internally, there are three basic kinds of classes: classes that are
 * never matched, and must be assigned through classification rules (e.g.,
 * known-clients and unknown-clients, above), classes that are assigned
 * by doing a hash lookup, and classes that must be matched on an individual
 * basis.   These classes are all declared the same way:
 *
 * class [<class-name>] {
 *     match if <match-expr>;
 *     ...
 * }
 *
 * It is possible to declare a class that spawns other classes - if a client
 * matches the class, a new class is created that matches the client's
 * parameters more specifically.   Classes that are created in this way are
 * attached to the class that spawned them with a hash table, and if a client
 * matches the hash, the more general test is not done.   Care should be taken
 * in constructing such classes: a poorly-chosen spawn test can cause such a
 * class to grow without bound.
 *
 * class [<class-name>] {
 *     match if <match-expr>;
 *     spawn <spawn-expr>;
 * }
 *
 * Testing a whole litany of classes can take quite a bit of time for each
 * incoming packet.   In order to make this process more efficient, it may
 * be desirable to group classes into collections, and then write a more
 * complicated set of classification rules so as to perform fewer tests.
 * Classes can be grouped into collections by writing a collection statement
 * in the class declaration:
 *
 *     collection <collection-name>;
 * 
 * By default, all classes are members of the "default" collection.
 *
 * Beware: if you declare a class to be part of a collection other than
 * "default" but do not update the classification rules, that class will 
 * never be considered during the client classification process.
 */

/*
 * Expressions used to make matches:
 *
 * expression :== LPAREN expression RPAREN |
 *		  expression OR expression |
 *		  expression AND expression |
 *		  NOT expression |
 *		  test_expr
 *
 * test_expr :== extract_expr EQUALS extract_expr |
 *		 CHECK_COLLECTION STRING
 *
 * extract_expr :== SUBSTRING extract_expr NUMBER NUMBER |
 *		    SUFFIX extract_expr NUMBER |
 *		    OPTION IDENTIFIER DOT IDENTIFIER |
 *		    OPTION IDENTIFIER |
 *		    CHADDR
 *		    HTYPE
 *		    HARDWARE
 *		    data_expr
 *
 * data_expr :== STRING |
 *		 hex_data_expr
 *
 * hex_data_expr :== HEX_NUMBER |
 *		     hex_data_expr COLON HEX_NUMBER
 *
 * For example:
 *
 *   chaddr = 08:00:2b:4c:2a:29 AND htype = 1;
 *
 *   substring chaddr 0 3 = 08:00:2b;
 *
 *   substring dhcp-client-identifier 1 3 = "RAS";
 *
 *   substring relay.circuit-id = 04:2c:59:31;
 */ 

/*
 * Clients are classified based on classification rules, which can be
 * specified on a per-group basis.   By default, the following classification
 * rules apply:
 *
 * classification-rules {
 *	check-collection "default";
 *  }
 *
 */

struct class unknown_class = {
	(struct class *)0,
	"unknown",
	(struct hash_table *)0,
	(struct expression *)0,
	(struct expression *)0,
	(struct group *)0,
};

struct class known_class = {
	(struct class *)0,
	"unknown",
	(struct hash_table *)0,
	(struct expression *)0,
	(struct expression *)0,
	(struct group *)0,
};

struct collection default_collection = {
	(struct collection *)0,
	"default",
	(struct class *)0,
};

struct collection *collections = &default_collection;
struct executable_statement *default_classification_rules;

/* Build the default classification rule tree. */

void classification_setup ()
{
	struct executable_statement *rules;
	struct expression *me;

	/* check-collection "default" */
	me = (struct expression *)dmalloc (sizeof (struct expression),
					   "default check expression");
	if (!me)
		error ("Can't allocate default check expression");
	memset (me, 0, sizeof *me);
	me -> op = expr_check;
	me -> data.check = &default_collection;
	
	/* eval ... */
	rules = (struct executable_statement *)
		dmalloc (sizeof (struct executable_statement),
			 "add default collection check rule");
	if (!rules)
		error ("Can't allocate check of default collection");
	memset (rules, 0, sizeof *rules);
	rules -> op = eval_statement;
	rules -> data.eval = me;

	default_classification_rules = rules;
}

void classify_client (packet)
	struct packet *packet;
{
	execute_statements (packet, &packet -> options,
			    (struct option_state *)0,
			    default_classification_rules);
}

int check_collection (packet, collection)
	struct packet *packet;
	struct collection *collection;
{
	struct class *class, *nc;
	struct data_string data;
	int matched = 0;
	int status;

	for (class = collection -> classes; class; class = class -> nic) {
		if (class -> hash) {
			memset (&data, 0, sizeof data);
			status = evaluate_data_expression (&data, packet,
							   &packet -> options,
							   class -> spawn);
			if (status &&
			    (nc = (struct class *)hash_lookup (class -> hash,
							       data.data,
							       data.len))) {
				classify (packet, class);
				matched = 1;
				continue;
			}
		}
		memset (&data, 0, sizeof data);
		if ((matched =
		     evaluate_boolean_expression_result (packet,
							 &packet -> options,
							 class -> expr) &&
		    class -> spawn &&
		    evaluate_data_expression (&data, packet,
					      &packet -> options,
					      class -> spawn))) {
			nc = (struct class *)
				dmalloc (sizeof (struct class), "class spawn");
			memset (nc, 0, sizeof *nc);
			nc -> group = class -> group;
			if (!class -> hash)
				class -> hash = new_hash ();
			add_hash (class -> hash,
				  data.data, data.len,
				  (unsigned char *)nc);
			classify (packet, nc);
		} else
			classify (packet, class);
		matched = 1;
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
		warn ("too many groups for %s",
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
