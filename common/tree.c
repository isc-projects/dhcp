/* tree.c

   Routines for manipulating parse trees... */

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
"$Id: tree.c,v 1.12 1998/06/25 03:10:32 mellon Exp $ Copyright (c) 1995, 1996, 1997, 1998 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

static struct data_string do_host_lookup PROTO ((struct dns_host_entry *));

pair cons (car, cdr)
	caddr_t car;
	pair cdr;
{
	pair foo = (pair)dmalloc (sizeof *foo, "cons");
	if (!foo)
		error ("no memory for cons.");
	foo -> car = car;
	foo -> cdr = cdr;
	return foo;
}

struct expression *make_host_lookup (name)
	char *name;
{
	struct expression *nt;
	nt = new_expression ("make_host_lookup");
	if (!nt)
		error ("No memory for host lookup tree node.");
	nt -> op = expr_host_lookup;
	nt -> data.host_lookup = enter_dns_host (name);
	return nt;
}

struct dns_host_entry *enter_dns_host (name)
	char *name;
{
	struct dns_host_entry *dh;

	if (!(dh = (struct dns_host_entry *)dmalloc
	      (sizeof (struct dns_host_entry), "enter_dns_host")))
		error ("Can't allocate space for new host.");
	memset (dh, 0, sizeof *dh);

	dh -> hostname = dmalloc (strlen (name) + 1, "enter_dns_host");
	strcpy (dh -> hostname, name);
	return dh;
}

struct expression *make_const_data (data, len, terminated, allocate)
	unsigned char *data;
	int len;
	int terminated;
	int allocate;
{
	struct expression *nt;
	if (!(nt = new_expression ("tree_const")))
		error ("No memory for constant data tree node.");
	memset (nt, 0, sizeof *nt);
	if (len) {
		if (allocate) {
			if (!(nt -> data.const_data.data =
			      (unsigned char *)dmalloc (len + terminated,
							"tree_const")))
				error ("No memory for const_data node.");
			memcpy (nt -> data.const_data.data,
				data, len + terminated);
			nt -> data.const_data.buffer =
				nt -> data.const_data.data;
		} else
			nt -> data.const_data.data = data;
		nt -> data.const_data.terminated = terminated;
	} else
		nt -> data.const_data.data = 0;

	nt -> op = expr_const_data;
	nt -> data.const_data.len = len;
	return nt;
}

struct expression *make_concat (left, right)
	struct expression *left, *right;
{
	struct expression *nt;

	/* If we're concatenating a null tree to a non-null tree, just
	   return the non-null tree; if both trees are null, return
	   a null tree. */
	if (!left)
		return right;
	if (!right)
		return left;

	/* If both expressions are constant, combine them. */
	if (left -> op == expr_const_data &&
	    right -> op == expr_const_data) {
		unsigned char *buf =
			dmalloc (left -> data.const_data.len
				 + right -> data.const_data.len
				 + right -> data.const_data.terminated,
				 "tree_concat");
		if (!buf)
			error ("No memory to concatenate constants.");
		memcpy (buf, left -> data.const_data.data,
			left -> data.const_data.len);
		memcpy (buf + left -> data.const_data.len,
			right -> data.const_data.data,
			right -> data.const_data.len);
		if (left -> data.const_data.buffer)
			dfree (left -> data.const_data.buffer, "make_concat");
		if (right -> data.const_data.buffer)
			dfree (right -> data.const_data.buffer, "make_concat");
		left -> data.const_data.data = buf;
		left -> data.const_data.buffer = buf;
		left -> data.const_data.len += right -> data.const_data.len;
		free_expression (right, "make_concat");
		return left;
	}
			
	/* Otherwise, allocate a new node to concatenate the two. */
	if (!(nt = new_expression ("make_concat")))
		error ("No memory for concatenation expression node.");
	nt -> op = expr_concat;
	nt -> data.concat [0] = left;
	nt -> data.concat [1] = right;
	return nt;
}

struct expression *make_substring (expr, offset, length)
	struct expression *expr;
	struct expression *offset;
	struct expression *length;
{
	struct expression *rv;

	/* If the expression we're limiting is constant, limit it now. */
	if (expr -> op == expr_const_data &&
	    offset -> op == expr_const_int &&
	    length -> op == expr_const_int) {
		int off = offset -> data.const_int;
		int len = length -> data.const_int;
		if (expr -> data.const_data.len > off) {
			expr -> data.const_data.data += off;
			expr -> data.const_data.len -= off;
			if (expr -> data.const_data.len > len) {
				expr -> data.const_data.len = len;
				expr -> data.const_data.terminated = 0;
			}
		} else {
			expr -> data.const_data.len = 0;
			expr -> data.const_data.terminated = 0;
		}

		free_expression (offset, "make_substring");
		free_expression (length, "make_substring");
		return expr;
	}

	/* Otherwise, put in a node which enforces the limit on evaluation. */
	rv = new_expression ("make_substring");
	if (!rv)
		error ("no memory for substring expression.");
	memset (rv, 0, sizeof *rv);
	rv -> op = expr_substring;
	rv -> data.substring.expr = expr;
	rv -> data.substring.offset = offset;
	rv -> data.substring.len = length;
	return rv;
}

struct expression *make_limit (expr, limit)
	struct expression *expr;
	int limit;
{
	struct expression *rv;

	/* If the expression we're limiting is constant, limit it now. */
	if (expr -> op == expr_const_data) {
		if (expr -> data.const_data.len > limit) {
			expr -> data.const_data.len = limit;
			expr -> data.const_data.terminated = 0;
		}
		return expr;
	}

	/* Otherwise, put in a node which enforces the limit on evaluation. */
	rv = new_expression ("make_limit 1");
	if (!rv)
		error ("no memory for limit expression");
	memset (rv, 0, sizeof *rv);
	rv -> op = expr_substring;
	rv -> data.substring.expr = expr;

	/* Offset is a constant 0. */
	rv -> data.substring.offset = new_expression ("make_limit 2");
	if (!rv -> data.substring.offset)
		error ("no memory for limit offset expression");
	memset (rv -> data.substring.offset, 0, sizeof *rv);
	rv -> data.substring.offset -> op = expr_const_int;
	rv -> data.substring.offset -> data.const_int = 0;

	/* Length is a constant: the specified limit. */
	rv -> data.substring.len = new_expression ("make_limit 2");
	if (!rv -> data.substring.len)
		error ("no memory for limit length expression");
	memset (rv -> data.substring.len, 0, sizeof *rv);
	rv -> data.substring.offset -> op = expr_const_int;
	rv -> data.substring.offset -> data.const_int = limit;

	return rv;
}

struct option_cache *option_cache (expr, option)
	struct expression *expr;
	struct option *option;
{
	struct option_cache *oc = new_option_cache ("option_cache");
	if (!oc) {
		warn ("no memory for option cache.");
		return (struct option_cache *)0;
	}
	memset (oc, 0, sizeof *oc);
	oc -> expression = expr;
	oc -> option = option;
	return oc;
}

static struct data_string do_host_lookup (dns)
	struct dns_host_entry *dns;
{
	struct hostent *h;
	int i;
	int new_len;
	struct data_string result;

	memset (&result, 0, sizeof result);

#ifdef DEBUG_EVAL
	debug ("time: now = %d  dns = %d %d  diff = %d",
	       cur_time, dns -> timeout, cur_time - dns -> timeout);
#endif

	/* If the record hasn't timed out, just copy the data and return. */
	if (cur_time <= dns -> timeout) {
#ifdef DEBUG_EVAL
		debug ("easy copy: %x %d %s",
		       dns -> data, dns -> data.len,
		       dns -> data.data
		       ? inet_ntoa (*(struct in_addr *)(dns -> data.data))
		       : 0);
#endif
		result.data = dns -> buffer;
		result.len = dns -> data_len;
		return result;
	}
#ifdef DEBUG_EVAL
	debug ("Looking up %s", dns -> hostname);
#endif

	/* Otherwise, look it up... */
	h = gethostbyname (dns -> hostname);
	if (!h) {
#ifndef NO_H_ERRNO
		switch (h_errno) {
		      case HOST_NOT_FOUND:
#endif
			warn ("%s: host unknown.", dns -> hostname);
#ifndef NO_H_ERRNO
			break;
		      case TRY_AGAIN:
			warn ("%s: temporary name server failure",
			      dns -> hostname);
			break;
		      case NO_RECOVERY:
			warn ("%s: name server failed", dns -> hostname);
			break;
		      case NO_DATA:
			warn ("%s: no A record associated with address",
			      dns -> hostname);
		}
#endif /* !NO_H_ERRNO */

		/* Okay to try again after a minute. */
		dns -> timeout = cur_time + 60;
		return result;
	}

#ifdef DEBUG_EVAL
	debug ("Lookup succeeded; first address is %s",
	       inet_ntoa (h -> h_addr_list [0]));
#endif

	/* Count the number of addresses we got... */
	for (i = 0; h -> h_addr_list [i]; i++)
		;
	
	/* Do we need to allocate more memory? */
	new_len = i * h -> h_length;
	if (dns -> buf_len < i) {
		unsigned char *buf =
			(unsigned char *)dmalloc (new_len, "do_host_lookup");
		/* If we didn't get more memory, use what we have. */
		if (!buf) {
			new_len = dns -> buf_len;
			if (!dns -> buf_len) {
				dns -> timeout = cur_time + 60;
				return result;
			}
		} else {
			if (dns -> buffer)
				dfree (dns -> buffer, "do_host_lookup");
			dns -> buffer = buf;
			dns -> buf_len = new_len;
		}
	}

	/* Addresses are conveniently stored one to the buffer, so we
	   have to copy them out one at a time... :'( */
	for (i = 0; i < new_len / h -> h_length; i++) {
		memcpy (dns -> buffer + h -> h_length * i,
			h -> h_addr_list [i], h -> h_length);
	}
#ifdef DEBUG_EVAL
	debug ("dns -> data: %x  h -> h_addr_list [0]: %x",
	       *(int *)(dns -> buffer), h -> h_addr_list [0]);
#endif
	dns -> data_len = new_len;

	/* Set the timeout for an hour from now.
	   XXX This should really use the time on the DNS reply. */
	dns -> timeout = cur_time + 3600;

#ifdef DEBUG_EVAL
	debug ("hard copy: %x %d %x",
	       dns -> data, dns -> data_len, *(int *)(dns -> data));
#endif
	result.data = dns -> buffer;
	result.len = dns -> data_len;
	return result;
}

int evaluate_boolean_expression (packet, expr)
	struct packet *packet;
	struct expression *expr;
{
	struct data_string left, right;
	int result;

	switch (expr -> op) {
	      case expr_check:
		return check_collection (packet, expr -> data.check);

	      case expr_equal:
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
			dfree ("evaluate_boolean_expression", left.buffer);
		if (right.buffer)
			dfree ("evaluate_boolean_expression", right.buffer);
		return result;

	      case expr_and:
		return (evaluate_boolean_expression (packet,
						     expr -> data.and [0]) &&
			evaluate_boolean_expression (packet,
						     expr -> data.and [1]));

	      case expr_or:
		return (evaluate_boolean_expression (packet,
						     expr -> data.or [0]) ||
			evaluate_boolean_expression (packet,
						     expr -> data.or [1]));

	      case expr_not:
		return (!evaluate_boolean_expression (packet,
						      expr -> data.not));

	      case expr_substring:
	      case expr_suffix:
	      case expr_option:
	      case expr_hardware:
	      case expr_const_data:
	      case expr_packet:
	      case expr_concat:
	      case expr_host_lookup:
		warn ("Data opcode in evaluate_boolean_expression: %d",
		      expr -> op);
		return 0;

	      case expr_extract_int8:
	      case expr_extract_int16:
	      case expr_extract_int32:
	      case expr_const_int:
		warn ("Numeric opcode in evaluate_boolean_expression: %d",
		      expr -> op);
		return 0;
	}

	warn ("Bogus opcode in evaluate_boolean_expression: %d", expr -> op);
	return 0;
}

struct data_string evaluate_data_expression (packet, expr)
	struct packet *packet;
	struct expression *expr;
{
	struct data_string result, data, other;
	int offset, len;

	switch (expr -> op) {
		/* Extract N bytes starting at byte M of a data string. */
	      case expr_substring:
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
				dfree ("expr_substring", data.buffer);
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
	      case expr_suffix:
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
	      case expr_option:
		return ((*expr -> data.option -> universe -> lookup_func)
			(packet, expr -> data.option -> code));

		/* Combine the hardware type and address. */
	      case expr_hardware:
		result.len = packet -> raw -> hlen + 1;
		result.buffer = dmalloc (result.len,
					 "expr_hardware");
		if (!result.buffer) {
			warn ("no memory for expr_hardware");
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
	      case expr_packet:
		len = evaluate_numeric_expression (packet,
						   expr -> data.packet.len);
		offset = evaluate_numeric_expression (packet,
						      expr -> data.packet.len);
		if (offset > packet -> packet_length) {
			warn ("expr_packet on %s: length %d + offset %d > %d",
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
	      case expr_const_data:
		return expr -> data.const_data;

		/* Hostname lookup... */
	      case expr_host_lookup:
		return do_host_lookup (expr -> data.host_lookup);
		break;

		/* Concatenation... */
	      case expr_concat:
		data = evaluate_data_expression (packet,
						 expr -> data.concat [0]);
		other = evaluate_data_expression (packet,
						  expr -> data.concat [1]);

		memset (&result, 0, sizeof result);
		result.buffer = dmalloc (data.len + other.len +
					 other.terminated, "expr_concat");
		if (!result.buffer) {
			warn ("out of memory doing concatenation.");
			return result;
		}

		result.len = (data.len + other.len);
		result.data = result.buffer;
		memcpy (result.data, data.data, data.len);
		memcpy (&result.data [data.len], other.data,
			other.len + other.terminated);
		if (data.buffer)
			dfree (data.buffer, "expr_concat");
		if (other.buffer)
			dfree (other.buffer, "expr_concat");
		return result;
		break;

	      case expr_check:
	      case expr_equal:
	      case expr_and:
	      case expr_or:
	      case expr_not:
		warn ("Boolean opcode in evaluate_data_expression: %d",
		      expr -> op);
		goto null_return;

	      case expr_extract_int8:
	      case expr_extract_int16:
	      case expr_extract_int32:
	      case expr_const_int:
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
	struct expression *expr;
{
	struct data_string data;
	unsigned long result;

	switch (expr -> op) {
	      case expr_check:
	      case expr_equal:
	      case expr_and:
	      case expr_or:
	      case expr_not:
		warn ("Boolean opcode in evaluate_numeric_expression: %d",
		      expr -> op);
		return 0;

	      case expr_substring:
	      case expr_suffix:
	      case expr_option:
	      case expr_hardware:
	      case expr_const_data:
	      case expr_packet:
	      case expr_concat:
	      case expr_host_lookup:
		warn ("Data opcode in evaluate_numeric_expression: %d",
		      expr -> op);
		return 0;

	      case expr_extract_int8:
		data = evaluate_data_expression (packet,
						 expr ->
						 data.extract_int.expr);
		if (data.len < 1)
			return 0;
		result = data.data [0];
		if (data.buffer)
			dfree (data.buffer, "expr_extract_int8");
		return result;

	      case expr_extract_int16:
		data = evaluate_data_expression (packet,
						 expr ->
						 data.extract_int.expr);
		if (data.len < 2)
			return 0;
		result =  getUShort (data.data);
		if (data.buffer)
			dfree (data.buffer, "expr_extract_int16");
		return result;

	      case expr_extract_int32:
		data = evaluate_data_expression (packet,
						 expr ->
						 data.extract_int.expr);
		if (data.len < 4)
			return 0;
		result =  getULong (data.data);
		if (data.buffer)
			dfree (data.buffer, "expr_extract_int32");
		return result;

	      case expr_const_int:
		return expr -> data.const_int;
	}

	warn ("Bogus opcode in evaluate_numeric_expression: %d", expr -> op);
	return 0;
}

void free_oc_ephemeral_state (oc)
	struct option_cache *oc;
{
	if (free_ephemeral_outer_tree (expr))
		free_option_cache (oc, "free_oc_ephemeral_state");
}

/* Recursively free any ephemeral subexpressions of the passed expression,
   and then free that expression. */

int free_ephemeral_outer_tree (expr)
	struct expression *expr;
{
	/* If this expression isn't ephemeral, notify the caller. */
	if (!(expr -> flags & EXPR_EPHEMERAL))
		return 0;

	/* Free any ephemeral subexpressions... */
	switch (expr -> op) {
		/* All the binary operators can be handled the same way. */
	      case expr_equal:
	      case expr_concat:
	      case expr_and:
	      case expr_or:
		free_ephemeral_outer_tree (expr -> data.equal [0]);
		free_ephemeral_outer_tree (expr -> data.equal [1]);
		break;

	      case expr_substring:
		free_ephemeral_outer_tree (expr -> data.substring.expr);
		free_ephemeral_outer_tree (expr -> data.substring.offset);
		free_ephemeral_outer_tree (expr -> data.substring.len);
		break;

	      case expr_suffix:
		free_ephemeral_outer_tree (expr -> data.suffix.expr);
		free_ephemeral_outer_tree (expr -> data.suffix.len);
		break;

	      case expr_not:
		free_ephemeral_outer_tree (expr -> data.not);
		break;

	      case expr_packet:
		free_ephemeral_outer_tree (expr -> data.packet.offset);
		free_ephemeral_outer_tree (expr -> data.packet.len);
		break;

	      case expr_extract_int8:
	      case expr_extract_int16:
	      case expr_extract_int32:
		free_ephemeral_outer_tree (expr -> data.extract_int.expr);
		free_ephemeral_outer_tree (expr -> data.extract_int.width);
		break;

		/* No subexpressions. */
	      case expr_const_int:
	      case expr_check:
	      case expr_host_lookup:
	      case expr_option:
	      case expr_const_data:
	      case expr_hardware:
		break;

	      default:
		break;
	}

	free_expression (expr, "free_expr_outer_tree");
	return 1;
}

/* Free all of the state in an option state buffer.   The buffer itself is
   not freed, since these buffers are always contained in other structures. */

void free_option_state (state)
	struct option_state *state;
{
	int i;
	struct agent_option *ao;
