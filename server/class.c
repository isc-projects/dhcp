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
"$Id: class.c,v 1.2 1998/04/20 18:03:33 mellon Exp $ Copyright (c) 1998 The Internet Software Consortium.  All rights reserved.\n";
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
 * match_expr :== LPAREN match_expr RPAREN |
 *		  match_expr OR match_expr |
 *		  match_expr AND match_expr |
 *		  NOT match_expr |
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
 *	if chaddr in known-hardware {
 *		add-class "known-clients";
 *	} else {
 *		add-class "unknown-clients";
 *	}
 *
 *	check-collection "default";
 *  }
 *
 */

struct class unknown_class = {
	(struct class *)0,
	"unknown",
	(struct hash_table *)0,
	(struct match_expr *)0,
	(struct match_expr *)0,
	(struct group *)0,
};

struct class known_class = {
	(struct class *)0,
	"unknown",
	(struct hash_table *)0,
	(struct match_expr *)0,
	(struct match_expr *)0,
	(struct group *)0,
};

struct collection default_collection = {
	(struct collection *)0,
	"default",
	(struct class *)0,
};

struct collection *collections = &default_collection;
struct classification_rule *default_classification_rules;
struct named_hash *named_hashes;
struct named_hash *known_hardware_hash;

/* Build the default classification rule tree. */

void classification_setup ()
{
	struct classification_rule *rules;
	struct match_expr *me;

	/* check-collection "default" */
	me = (struct match_expr *)dmalloc (sizeof (struct match_expr),
					   "default check expression");
	if (!me)
		error ("Can't allocate default check expression");
	memset (me, 0, sizeof *me);
	me -> op = match_check;
	me -> data.check = &default_collection;
	
	/* eval ... */
	rules = (struct classification_rule *)
		dmalloc (sizeof (struct classification_rule),
			 "add default collection check rule");
	if (!rules)
		error ("Can't allocate check of default collection");
	memset (rules, 0, sizeof *rules);
	rules -> op = classify_eval;
	rules -> data.eval = me;

	default_classification_rules = rules;
}

void classify_client (packet)
	struct packet *packet;
{
	run_classification_ruleset (packet, default_classification_rules);
}

int run_classification_ruleset (packet, ruleset)
	struct packet *packet;
	struct classification_rule *ruleset;
{
	struct classification_rule *r;

	for (r = ruleset; r; r = r -> next) {
		switch (r -> op) {
		      case classify_if:
			if (!run_classification_ruleset
			    (packet,
			     evaluate_match_expression (packet,
							r -> data.ie.expr)
			     ? r -> data.ie.true : r -> data.ie.false))
				return 0;
			break;

		      case classify_eval:
			evaluate_match_expression (packet, r -> data.eval);
			break;

		      case classify_add:
			classify (packet, r -> data.add);
			break;

		      case classify_break:
			return 0;

		      default:
			error ("bogus classification rule type %d\n", r -> op);
		}
	}

	return 1;
}

int evaluate_match_expression (packet, expr)
	struct packet *packet;
	struct match_expr *expr;
{
	struct data_string left, right;
	int result;

	switch (expr -> op) {
	      case match_check:
		return check_collection (packet, expr -> data.check);

	      case match_equal:
		left = evaluate_data_expression (packet,
						 expr -> data.equal [0]);
		right = evaluate_data_expression (packet,
						  expr -> data.equal [1]);
		if (left.len == right.len && !memcmp (left.data,
						      right.data, left.len))
			result = 1;
		else
			result = 0;
		if (left.buffer)
			dfree ("evaluate_match_expression", left.buffer);
		if (right.buffer)
			dfree ("evaluate_match_expression", right.buffer);
		return result;

	      case match_and:
		return (evaluate_match_expression (packet,
						   expr -> data.and [0]) &&
			evaluate_match_expression (packet,
						   expr -> data.and [1]));

	      case match_or:
		return (evaluate_match_expression (packet,
						   expr -> data.or [0]) ||
			evaluate_match_expression (packet,
						   expr -> data.or [1]));

	      case match_not:
		return (!evaluate_match_expression (packet, expr -> data.not));

#if 0
	      case match_in:
		left = evaluate_data_expression (packet, expr -> data.in.expr);
		return (int)hash_lookup (expr -> data.in.hash -> hash,
					 left.data, left.len);
#endif

	      case match_substring:
	      case match_suffix:
	      case match_option:
	      case match_hardware:
	      case match_const_data:
	      case match_packet:
		warn ("Data opcode in evaluate_match_expression: %d",
		      expr -> op);
		return 0;

	      case match_extract_int8:
	      case match_extract_int16:
	      case match_extract_int32:
	      case match_const_int:
		warn ("Numeric opcode in evaluate_match_expression: %d",
		      expr -> op);
		return 0;
	}

	warn ("Bogus opcode in evaluate_match_expression: %d", expr -> op);
	return 0;
}

struct data_string evaluate_data_expression (packet, expr)
	struct packet *packet;
	struct match_expr *expr;
{
	struct data_string result, data;
	int offset, len;

	switch (expr -> op) {
		/* Extract N bytes starting at byte M of a data string. */
	      case match_substring:
		data = evaluate_data_expression (packet,
						 expr -> data.substring.expr);

		/* Evaluate the offset and length. */
		offset = evaluate_numeric_expression
			(packet, expr -> data.substring.offset);
		len = evaluate_numeric_expression
			(packet, expr -> data.substring.len);

		/* If the offset is after end of the string, return
		   an empty string. */
		if (data.len <= offset) {
			if (data.buffer)
				dfree ("match_substring", data.buffer);
			memset (&result, 0, sizeof result);
			return result;
		}

		/* Otherwise, do the adjustments and return what's left. */
		data.len -= offset;
		if (data.len > len) {
			data.len = len;
			data.terminated = 0;
		}
		data.data += offset;
		return data;

		/* Extract the last N bytes of a data string. */
	      case match_suffix:
		data = evaluate_data_expression (packet,
						 expr -> data.suffix.expr);

		/* Evaluate the length. */
		len = evaluate_numeric_expression
			(packet, expr -> data.substring.len);

		/* If we are returning the last N bytes of a string whose
		   length is <= N, just return the string. */
		if (data.len <= len)
			return data;
		data.data += data.len - len;
		data.len = len;
		return data;

		/* Extract an option. */
	      case match_option:
		return ((*expr -> data.option -> universe -> lookup_func)
			(packet, expr -> data.option -> code));

		/* Combine the hardware type and address. */
	      case match_hardware:
		result.len = packet -> raw -> hlen + 1;
		result.buffer = dmalloc (result.len,
					 "match_hardware");
		if (!result.buffer) {
			warn ("no memory for match_hardware");
			result.len = 0;
		} else {
			result.buffer [0] = packet -> raw -> htype;
			memcpy (&result.buffer [1], packet -> raw -> chaddr,
				packet -> raw -> hlen);
		}
		result.data = result.buffer;
		result.terminated = 0;
		return result;

		/* Extract part of the raw packet. */
	      case match_packet:
		len = evaluate_numeric_expression (packet,
						   expr -> data.packet.len);
		offset = evaluate_numeric_expression (packet,
						      expr -> data.packet.len);
		if (offset > packet -> packet_length) {
			warn ("match_packet on %s: length %d + offset %d > %d",
			      print_hw_addr (packet -> raw -> htype,
					     packet -> raw -> hlen,
					     packet -> raw -> chaddr),
			      len, offset, packet -> packet_length);
			memset (&result, 0, sizeof result);
			return result;
		}
		if (offset + len > packet -> packet_length)
			result.len = packet -> packet_length - offset;
		else
			result.len = len;
		result.data = ((unsigned char *)(packet -> raw)) + offset;
		result.buffer = (unsigned char *)0;
		result.terminated = 0;
		return result;

		/* Some constant data... */
	      case match_const_data:
		return expr -> data.const_data;

	      case match_check:
	      case match_equal:
	      case match_and:
	      case match_or:
	      case match_not:
		warn ("Boolean opcode in evaluate_data_expression: %d",
		      expr -> op);
		goto null_return;

	      case match_extract_int8:
	      case match_extract_int16:
	      case match_extract_int32:
	      case match_const_int:
		warn ("Numeric opcode in evaluate_data_expression: %d",
		      expr -> op);
		goto null_return;
	}

	warn ("Bogus opcode in evaluate_data_expression: %d", expr -> op);
      null_return:
	memset (&result, 0, sizeof result);
	return result;
}	

unsigned long evaluate_numeric_expression (packet, expr)
	struct packet *packet;
	struct match_expr *expr;
{
	struct data_string data;
	unsigned long result;

	switch (expr -> op) {
	      case match_check:
	      case match_equal:
	      case match_and:
	      case match_or:
	      case match_not:
		warn ("Boolean opcode in evaluate_numeric_expression: %d",
		      expr -> op);
		return 0;

	      case match_substring:
	      case match_suffix:
	      case match_option:
	      case match_hardware:
	      case match_const_data:
	      case match_packet:
		warn ("Data opcode in evaluate_numeric_expression: %d",
		      expr -> op);
		return 0;

	      case match_extract_int8:
		data = evaluate_data_expression (packet,
						 expr ->
						 data.extract_int.expr);
		if (data.len < 1)
			return 0;
		return data.data [0];

	      case match_extract_int16:
		data = evaluate_data_expression (packet,
						 expr ->
						 data.extract_int.expr);
		if (data.len < 2)
			return 0;
		return getUShort (data.data);

	      case match_extract_int32:
		data = evaluate_data_expression (packet,
						 expr ->
						 data.extract_int.expr);
		if (data.len < 4)
			return 0;
		return getULong (data.data);

	      case match_const_int:
		return expr -> data.const_int;
	}

	warn ("Bogus opcode in evaluate_numeric_expression: %d", expr -> op);
	return 0;
}

int check_collection (packet, collection)
	struct packet *packet;
	struct collection *collection;
{
	struct class *class, *nc;
	struct data_string data;
	int matched = 0;

	for (class = collection -> classes; class; class = class -> nic) {
		if (class -> hash) {
			data = evaluate_data_expression (packet,
							 class -> spawn);
			nc = (struct class *)hash_lookup (class -> hash,
							  data.data, data.len);
			if (nc) {
				classify (packet, class);
				matched = 1;
				continue;
			}
		}
		if (class -> expr &&
		    evaluate_match_expression (packet,
					       class -> expr)) {
			if (class -> spawn) {
				data = evaluate_data_expression
					(packet, class -> spawn);
				nc = (struct class *)
					dmalloc (sizeof (struct class),
						 "class spawn");
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

