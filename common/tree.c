/* tree.c

   Routines for manipulating parse trees... */

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
"$Id: tree.c,v 1.29 1999/05/27 14:30:00 mellon Exp $ Copyright (c) 1995, 1996, 1997, 1998 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

static int do_host_lookup PROTO ((struct data_string *,
				  struct dns_host_entry *));

pair cons (car, cdr)
	caddr_t car;
	pair cdr;
{
	pair foo = (pair)dmalloc (sizeof *foo, "cons");
	if (!foo)
		log_fatal ("no memory for cons.");
	foo -> car = car;
	foo -> cdr = cdr;
	return foo;
}

int make_const_option_cache (oc, buffer, data, len, option, name)
	struct option_cache **oc;
	struct buffer **buffer;
	u_int8_t *data;
	int len;
	struct option *option;
	char *name;
{
	struct buffer *bp;

	if (buffer) {
		bp = *buffer;
		*buffer = 0;
	} else {
		bp = (struct buffer *)0;
		if (!buffer_allocate (&bp, len, name)) {
			log_error ("%s: can't allocate buffer.", name);	
			return 0;
		}
	}

	if (!option_cache_allocate (oc, name)) {
		log_error ("%s: can't allocate option cache.");
		buffer_dereference (&bp, name);
		return 0;
	}

	(*oc) -> data.len = len;
	(*oc) -> data.data = &bp -> data [0];
	(*oc) -> data.terminated = 0;
	if (data)
		memcpy ((*oc) -> data.data, data, len);
	(*oc) -> option = option;
	return 1;
}

int make_host_lookup (expr, name)
	struct expression **expr;
	char *name;
{
	if (!expression_allocate (expr, "make_host_lookup")) {
		log_error ("No memory for host lookup tree node.");
		return 0;
	}
	(*expr) -> op = expr_host_lookup;
	if (!enter_dns_host (&((*expr) -> data.host_lookup), name)) {
		expression_dereference (expr, "make_host_lookup");
		return 0;
	}
	return 1;
}

int enter_dns_host (dh, name)
	struct dns_host_entry **dh;
	char *name;
{
	/* XXX This should really keep a hash table of hostnames
	   XXX and just add a new reference to a hostname that
	   XXX already exists, if possible, rather than creating
	   XXX a new structure. */
	if (!dns_host_entry_allocate (dh, name, "enter_dns_host")) {
		log_error ("Can't allocate space for new host.");
		return 0;
	}
	return 1;
}

int make_const_data (expr, data, len, terminated, allocate)
	struct expression **expr;
	unsigned char *data;
	int len;
	int terminated;
	int allocate;
{
	struct expression *nt;

	if (!expression_allocate (expr, "make_host_lookup")) {
		log_error ("No memory for make_const_data tree node.");
		return 0;
	}
	nt = *expr;

	if (len) {
		if (allocate) {
			if (!buffer_allocate (&nt -> data.const_data.buffer,
					      len + terminated,
					      "make_const_data")) {
				log_error ("Can't allocate const_data buffer");
				expression_dereference (expr,
							"make_const_data");
				return 0;
			}
			nt -> data.const_data.data =
				&nt -> data.const_data.buffer -> data [0];
			memcpy (nt -> data.const_data.data,
				data, len + terminated);
		} else 
			nt -> data.const_data.data = data;
		nt -> data.const_data.terminated = terminated;
	} else
		nt -> data.const_data.data = 0;

	nt -> op = expr_const_data;
	nt -> data.const_data.len = len;
	return 1;
}

int make_concat (expr, left, right)
	struct expression **expr;
	struct expression *left, *right;
{
	/* If we're concatenating a null tree to a non-null tree, just
	   return the non-null tree; if both trees are null, return
	   a null tree. */
	if (!left) {
		if (!right)
			return 0;
		expression_reference (expr, right, "make_concat");
		return 1;
	}
	if (!right) {
		expression_reference (expr, left, "make_concat");
		return 1;
	}
			
	/* Otherwise, allocate a new node to concatenate the two. */
	if (!expression_allocate (expr, "make_concat")) {
		log_error ("No memory for concatenation expression node.");
		return 0;
	}
		
	(*expr) -> op = expr_concat;
	expression_reference (&(*expr) -> data.concat [0],
			      left, "make_concat");
	expression_reference (&(*expr) -> data.concat [1],
			      right, "make_concat");
	return 1;
}

int make_encapsulation (expr, name)
	struct expression **expr;
	struct data_string *name;
{
	/* Allocate a new node to store the encapsulation. */
	if (!expression_allocate (expr, "make_encapsulation")) {
		log_error ("No memory for encapsulation expression node.");
		return 0;
	}
		
	(*expr) -> op = expr_encapsulate;
	data_string_copy (&(*expr) -> data.encapsulate,
			  name, "make_concat");
	return 1;
}

int make_substring (new, expr, offset, length)
	struct expression **new;
	struct expression *expr;
	struct expression *offset;
	struct expression *length;
{
	/* Allocate an expression node to compute the substring. */
	if (!expression_allocate (new, "make_substring")) {
		log_error ("no memory for substring expression.");
		return 0;
	}
	(*new) -> op = expr_substring;
	expression_reference (&(*new) -> data.substring.expr,
			      expr, "make_concat");
	expression_reference (&(*new) -> data.substring.offset,
			      offset, "make_concat");
	expression_reference (&(*new) -> data.substring.len,
			      length, "make_concat");
	return 1;
}

int make_limit (new, expr, limit)
	struct expression **new;
	struct expression *expr;
	int limit;
{
	struct expression *rv;

	/* Allocate a node to enforce a limit on evaluation. */
	if (!expression_allocate (new, "make_limit"))
		log_error ("no memory for limit expression");
	(*new) -> op = expr_substring;
	expression_reference (&(*new) -> data.substring.expr,
			      expr, "make_limit");

	/* Offset is a constant 0. */
	if (!expression_allocate (&(*new) -> data.substring.offset,
				  "make_limit")) {
		log_error ("no memory for limit offset expression");
		expression_dereference (new, "make_limit");
		return 0;
	}
	(*new) -> data.substring.offset -> op = expr_const_int;
	(*new) -> data.substring.offset -> data.const_int = 0;

	/* Length is a constant: the specified limit. */
	if (!expression_allocate (&(*new) -> data.substring.len,
				  "make_limit")) {
		log_error ("no memory for limit length expression");
		expression_dereference (new, "make_limit");
		return 0;
	}
	(*new) -> data.substring.len -> op = expr_const_int;
	(*new) -> data.substring.len -> data.const_int = limit;

	return 1;
}

int option_cache (oc, dp, expr, option)
	struct option_cache **oc;
	struct data_string *dp;
	struct expression *expr;
	struct option *option;
{
	if (!option_cache_allocate (oc, "option_cache"))
		return 0;
	if (dp)
		data_string_copy (&(*oc) -> data, dp, "option_cache");
	if (expr)
		expression_reference (&(*oc) -> expression,
				      expr, "option_cache");
	(*oc) -> option = option;
	return 1;
}

int do_host_lookup (result, dns)
	struct data_string *result;
	struct dns_host_entry *dns;
{
	struct hostent *h;
	int i, count;
	int new_len;

#ifdef DEBUG_EVAL
	log_debug ("time: now = %d  dns = %d %d  diff = %d",
	       cur_time, dns -> timeout, cur_time - dns -> timeout);
#endif

	/* If the record hasn't timed out, just copy the data and return. */
	if (cur_time <= dns -> timeout) {
#ifdef DEBUG_EVAL
		log_debug ("easy copy: %d %s",
		       dns -> data.len,
		       (dns -> data.len > 4
			? inet_ntoa (*(struct in_addr *)(dns -> data.data))
			: 0));
#endif
		data_string_copy (result, &dns -> data, "do_host_lookup");
		return 1;
	}
#ifdef DEBUG_EVAL
	log_debug ("Looking up %s", dns -> hostname);
#endif

	/* Otherwise, look it up... */
	h = gethostbyname (dns -> hostname);
	if (!h) {
#ifndef NO_H_ERRNO
		switch (h_errno) {
		      case HOST_NOT_FOUND:
#endif
			log_error ("%s: host unknown.", dns -> hostname);
#ifndef NO_H_ERRNO
			break;
		      case TRY_AGAIN:
			log_error ("%s: temporary name server failure",
			      dns -> hostname);
			break;
		      case NO_RECOVERY:
			log_error ("%s: name server failed", dns -> hostname);
			break;
		      case NO_DATA:
			log_error ("%s: no A record associated with address",
			      dns -> hostname);
		}
#endif /* !NO_H_ERRNO */

		/* Okay to try again after a minute. */
		dns -> timeout = cur_time + 60;
		data_string_forget (&dns -> data, "do_host_lookup");
		return 0;
	}

#ifdef DEBUG_EVAL
	log_debug ("Lookup succeeded; first address is %s",
	       inet_ntoa (h -> h_addr_list [0]));
#endif

	/* Count the number of addresses we got... */
	for (count = 0; h -> h_addr_list [count]; count++)
		;
	
	/* Dereference the old data, if any. */
	data_string_forget (&dns -> data, "do_host_lookup");

	/* Do we need to allocate more memory? */
	new_len = count * h -> h_length;
	if (!buffer_allocate (&dns -> data.buffer, new_len, "do_host_lookup"))
	{
		log_error ("No memory for %s.", dns -> hostname);
		return 0;
	}

	dns -> data.data = &dns -> data.buffer -> data [0];
	dns -> data.len = new_len;
	dns -> data.terminated = 0;

	/* Addresses are conveniently stored one to the buffer, so we
	   have to copy them out one at a time... :'( */
	for (i = 0; i < count; i++) {
		memcpy (&dns -> data.data [h -> h_length * i],
			h -> h_addr_list [i], h -> h_length);
	}
#ifdef DEBUG_EVAL
	log_debug ("dns -> data: %x  h -> h_addr_list [0]: %x",
	       *(int *)(dns -> buffer), h -> h_addr_list [0]);
#endif

	/* XXX Set the timeout for an hour from now.
	   XXX This should really use the time on the DNS reply. */
	dns -> timeout = cur_time + 3600;

#ifdef DEBUG_EVAL
	log_debug ("hard copy: %d %s", dns -> data.len,
	       (dns -> data.len > 4
		? inet_ntoa (*(struct in_addr *)(dns -> data.data)) : 0));
#endif
	data_string_copy (result, &dns -> data, "do_host_lookup");
	return 1;
}

int evaluate_boolean_expression (result, packet, options, expr)
	int *result;
	struct packet *packet;
	struct option_state *options;
	struct expression *expr;
{
	struct data_string left, right;
	int bleft, bright;
	int sleft, sright;

	switch (expr -> op) {
	      case expr_check:
		*result = check_collection (packet, expr -> data.check);
#if defined (DEBUG_EXPRESSIONS)
		log_info ("bool: check (%s) returns %s",
		      expr -> data.check -> name, *result ? "true" : "false");
#endif
		return 1;

	      case expr_equal:
		memset (&left, 0, sizeof left);
		sleft = evaluate_data_expression (&left, packet, options,
						  expr -> data.equal [0]);
		memset (&right, 0, sizeof right);
		sright = evaluate_data_expression (&right, packet, options,
						   expr -> data.equal [1]);
		if (sleft && sright) {
			if (left.len == right.len &&
			    !memcmp (left.data, right.data, left.len))
				*result = 1;
			else
				*result = 0;
		}

#if defined (DEBUG_EXPRESSIONS)
		log_info ("bool: equal (%s, %s) = %s",
		      sleft ? print_hex_1 (left.len, left.data, 30) : "NULL",
		      sright ? print_hex_2 (right.len,
					    right.data, 30) : "NULL",
		      ((sleft && sright)
		       ? (*result ? "true" : "false")
		       : "NULL"));
#endif
		if (sleft)
			data_string_forget (&left,
					    "evaluate_boolean_expression");
		if (sright)
			data_string_forget (&right,
					    "evaluate_boolean_expression");
		return sleft && sright;

	      case expr_and:
		sleft = evaluate_boolean_expression (&bleft, packet, options,
						     expr -> data.and [0]);
		sright = evaluate_boolean_expression (&bright, packet, options,
						      expr -> data.and [1]);

#if defined (DEBUG_EXPRESSIONS)
		log_info ("bool: and (%s, %s) = %s",
		      sleft ? (bleft ? "true" : "false") : "NULL",
		      sright ? (bright ? "true" : "false") : "NULL",
		      ((sleft && sright)
		       ? (bleft && bright ? "true" : "false") : "NULL"));
#endif
		if (sleft && sright) {
			*result = bleft && bright;
			return 1;
		}
		return 0;

	      case expr_or:
		sleft = evaluate_boolean_expression (&bleft, packet, options,
						     expr -> data.or [0]);
		sright = evaluate_boolean_expression (&bright, packet, options,
						      expr -> data.or [1]);
#if defined (DEBUG_EXPRESSIONS)
		log_info ("bool: or (%s, %s) = %s",
		      sleft ? (bleft ? "true" : "false") : "NULL",
		      sright ? (bright ? "true" : "false") : "NULL",
		      ((sleft && sright)
		       ? (bleft || bright ? "true" : "false") : "NULL"));
#endif
		if (sleft && sright) {
			*result = bleft || bright;
			return 1;
		}
		return 0;

	      case expr_not:
		sleft = evaluate_boolean_expression (&bleft, packet, options,
						     expr -> data.not);
#if defined (DEBUG_EXPRESSIONS)
		log_info ("bool: not (%s) = %s",
		      sleft ? (bleft ? "true" : "false") : "NULL",
		      ((sleft && sright)
		       ? (!bleft ? "true" : "false") : "NULL"));

#endif
		if (sleft) {
			*result = !bleft;
			return 1;
		}
		return 0;

	      case expr_exists:
		memset (&left, 0, sizeof left);
		if (!options ||
		    !((*expr -> data.option -> universe -> get_func)
		      (&left, expr -> data.exists -> universe,
		       options, expr -> data.exists -> code)))
			*result = 0;
		else {
			*result = 1;
			data_string_forget (&left,
					    "evaluate_boolean_expression");
		}
#if defined (DEBUG_EXPRESSIONS)
		log_info ("bool: exists %s.%s = %s",
		      expr -> data.option -> universe -> name,
		      expr -> data.option -> name, *result ? "true" : "false");
#endif
		return 1;

	      case expr_known:
		if (!packet) {
#if defined (DEBUG_EXPRESSIONS)
			log_info ("bool: known = NULL");
#endif
			return 0;
		}
#if defined (DEBUG_EXPRESSIONS)
		log_info ("bool: known = %s",
			  packet -> known ? "true" : "false");
#endif
		*result = packet -> known;
		return 1;

	      case expr_substring:
	      case expr_suffix:
	      case expr_option:
	      case expr_hardware:
	      case expr_const_data:
	      case expr_packet:
	      case expr_concat:
	      case expr_encapsulate:
	      case expr_host_lookup:
	      case expr_encode_int8:
	      case expr_encode_int16:
	      case expr_encode_int32:
		log_error ("Data opcode in evaluate_boolean_expression: %d",
		      expr -> op);
		return 0;

	      case expr_extract_int8:
	      case expr_extract_int16:
	      case expr_extract_int32:
	      case expr_const_int:
		log_error ("Numeric opcode in evaluate_boolean_expression: %d",
		      expr -> op);
		return 0;
	}

	log_error ("Bogus opcode in evaluate_boolean_expression: %d",
		   expr -> op);
	return 0;
}

int evaluate_data_expression (result, packet, options, expr)
	struct data_string *result;
	struct packet *packet;
	struct option_state *options;
	struct expression *expr;
{
	struct data_string data, other;
	unsigned long offset, len;
	int s0, s1, s2, s3;

	switch (expr -> op) {
		/* Extract N bytes starting at byte M of a data string. */
	      case expr_substring:
		memset (&data, 0, sizeof data);
		s0 = evaluate_data_expression (&data, packet, options,
					       expr -> data.substring.expr);

		/* Evaluate the offset and length. */
		s1 = evaluate_numeric_expression
			(&offset,
			 packet, options, expr -> data.substring.offset);
		s2 = evaluate_numeric_expression (&len, packet, options,
						  expr -> data.substring.len);

		if (s0 && s1 && s2) {
			/* If the offset is after end of the string,
			   return an empty string.  Otherwise, do the
			   adjustments and return what's left. */
			if (data.len > offset) {
				data_string_copy (result, &data,
						  "evaluate_data_expression");
				result -> len -= offset;
				if (result -> len > len) {
					result -> len = len;
					result -> terminated = 0;
				}
				result -> data += offset;
			}
			s3 = 1;
		} else
			s3 = 0;

#if defined (DEBUG_EXPRESSIONS)
		log_info ("data: substring (%s, %s, %s) = %s",
		      s0 ? print_hex_1 (data.len, data.data, 30) : "NULL",
		      s1 ? print_dec_1 (offset) : "NULL",
		      s2 ? print_dec_2 (len) : "NULL",
		      (s3 ? print_hex_2 (result -> len, result -> data, 30)
		          : "NULL"));
#endif
		if (s3)
			return 1;
		data_string_forget (&data, "evaluate_data_expression");
		return 0;


		/* Extract the last N bytes of a data string. */
	      case expr_suffix:
		memset (&data, 0, sizeof data);
		s0 = evaluate_data_expression (&data, packet, options,
					       expr -> data.suffix.expr);
		/* Evaluate the length. */
		s1 = evaluate_numeric_expression (&len, packet, options,
						  expr -> data.substring.len);
		if (s0 && s1) {
			data_string_copy (result, &data,
					  "evaluate_data_expression");

			/* If we are returning the last N bytes of a
			   string whose length is <= N, just return
			   the string - otherwise, compute a new
			   starting address and decrease the
			   length. */
			if (data.len > len) {
				result -> data += data.len - len;
				result -> len = len;
			}
		}

#if defined (DEBUG_EXPRESSIONS)
		log_info ("data: suffix (%s, %d) = %s",
		      s0 ? print_hex_1 (data.len, data.data, 30) : "NULL",
		      s1 ? print_dec_1 (len) : "NULL",
		      ((s0 && s1)
		       ? print_hex_2 (result -> len, result -> data, 30)
		       : NULL));
#endif
		return s0 && s1;

		/* Extract an option. */
	      case expr_option:
		if (options)
			s0 = ((*expr -> data.option -> universe -> get_func)
			      (result, expr -> data.option -> universe,
			       options, expr -> data.option -> code));
		else
			s0 = 0;

#if defined (DEBUG_EXPRESSIONS)
		log_info ("data: option %s.%s = %s",
		      expr -> data.option -> universe -> name,
		      expr -> data.option -> name,
		      s0 ? print_hex_1 (result -> len, result -> data, 60)
		      : "NULL");
#endif
		return s0;

		/* Combine the hardware type and address. */
	      case expr_hardware:
		if (!packet || !packet -> raw) {
			log_error ("data: hardware: raw packet not available");
			return 0;
		}
		if (packet -> raw -> hlen > sizeof packet -> raw -> chaddr) {
			log_error ("data: hardware: invalid hlen (%d)\n",
				   packet -> raw -> hlen);
			return 0;
		}
		result -> len = packet -> raw -> hlen + 1;
		if (buffer_allocate (&result -> buffer, result -> len,
				     "evaluate_data_expression")) {
			result -> data = &result -> buffer -> data [0];
			result -> data [0] = packet -> raw -> htype;
			memcpy (&result -> data [1], packet -> raw -> chaddr,
				packet -> raw -> hlen);
			result -> terminated = 0;
		} else {
			log_error ("data: hardware: no memory for buffer.");
			return 0;
		}
#if defined (DEBUG_EXPRESSIONS)
		log_info ("data: hardware = %s",
		      print_hex_1 (result -> len, result -> data, 60));
#endif
		return 1;

		/* Extract part of the raw packet. */
	      case expr_packet:
		if (!packet || !packet -> raw) {
			log_error ("data: packet: raw packet not available");
			return 0;
		}

		s0 = evaluate_numeric_expression (&len, packet, options,
						  expr -> data.packet.len);
		s1 = evaluate_numeric_expression (&offset, packet, options,
						  expr -> data.packet.len);
		if (s0 && s1 && offset < packet -> packet_length) {
			if (offset + len > packet -> packet_length)
				result -> len =
					packet -> packet_length - offset;
			else
				result -> len = len;
			if (buffer_allocate (&result -> buffer, result -> len,
					     "evaluate_data_expression")) {
				result -> data = &result -> buffer -> data [0];
				memcpy (result -> data,
					(((unsigned char *)(packet -> raw))
					 + offset), result -> len);
				result -> terminated = 0;
			} else {
				log_error ("data: packet: no buffer memory.");
				return 0;
			}
			s2 = 1;
		} else
			s2 = 0;
#if defined (DEBUG_EXPRESSIONS)
		log_info ("data: packet (%d, %d) = %s",
		      offset, len,
		      s2 ? print_hex_1 (result -> len,
					result -> data, 60) : NULL);
#endif
		return s2;

		/* The encapsulation of all defined options in an
		   option space... */
	      case expr_encapsulate:
		if (options)
			s0 = option_space_encapsulate
				(result, options, &expr -> data.encapsulate);
		else
			s0 = 0;

#if defined (DEBUG_EXPRESSIONS)
		log_info ("data: encapsulate (%s) = %s",
			  expr -> data.encapsulate.data,
			  s0 ? print_hex_1 (result -> len,
					    result -> data, 60) : "null");
#endif
		return s0;

		/* Some constant data... */
	      case expr_const_data:
#if defined (DEBUG_EXPRESSIONS)
		log_info ("data: const = %s",
		      print_hex_1 (expr -> data.const_data.len,
				   expr -> data.const_data.data, 60));
#endif
		data_string_copy (result,
				  &expr -> data.const_data,
				  "evaluate_data_expression");
		return 1;

		/* Hostname lookup... */
	      case expr_host_lookup:
		s0 = do_host_lookup (result, expr -> data.host_lookup);
#if defined (DEBUG_EXPRESSIONS)
		log_info ("data: DNS lookup (%s) = %s",
		      expr -> data.host_lookup -> hostname,
		      (s0
		       ? print_dotted_quads (result -> len, result -> data)
		       : "NULL"));
#endif
		return s0;

		/* Concatenation... */
	      case expr_concat:
		memset (&data, 0, sizeof data);
		s0 = evaluate_data_expression (&data, packet, options,
					       expr -> data.concat [0]);
		memset (&other, 0, sizeof other);
		s1 = evaluate_data_expression (&other, packet, options,
					       expr -> data.concat [1]);

		if (s0 && s1) {
			result -> len = data.len + other.len;
			if (!buffer_allocate (&result -> buffer,
					      (result -> len +
					       other.terminated),
					      "expr_concat")) {
				log_error ("data: concat: no memory");
				result -> len = 0;
				data_string_forget (&data, "expr_concat");
				data_string_forget (&other, "expr_concat");
				return 0;
			}
			result -> data = &result -> buffer -> data [0];
			memcpy (result -> data, data.data, data.len);
			memcpy (&result -> data [data.len],
				other.data, other.len + other.terminated);
		} else if (s0)
			data_string_copy (result, &data, "expr_concat");
		else if (s1)
			data_string_copy (result, &other, "expr_concat");
#if defined (DEBUG_EXPRESSIONS)
		log_info ("data: concat (%s, %s) = %s",
		      s0 ? print_hex_1 (data.len, data.data, 20) : "NULL",
		      s1 ? print_hex_2 (other.len, other.data, 20) : "NULL",
		      ((s0 || s1)
		       ? print_hex_3 (result -> len, result -> data, 30)
		       : "NULL"));
#endif
		return s0 || s1;

	      case expr_encode_int8:
		s0 = evaluate_numeric_expression (&len, packet, options,
						  expr -> data.packet.len);
		if (s0) {
			result -> len = 1;
			if (!buffer_allocate (&result -> buffer, 1,
					      "expr_encode_int8")) {
				log_error ("data: encode_int8: no memory");
				result -> len = 0;
				s0 = 0;
			} else {
				result -> data = &result -> buffer -> data [0];
				result -> data [0] = len;
			}
		} else
			result -> len = 0;

#if defined (DEBUG_EXPRESSIONS)
		if (!s0)
			log_info ("data: encode_int8 (NULL) = NULL");
		else
			log_info ("data: encode_int8 (%d) = %s", len,
				  print_hex_2 (result -> len,
					       result -> data, 20));
#endif
		return s0;
			
		
	      case expr_encode_int16:
		s0 = evaluate_numeric_expression (&len, packet, options,
						  expr -> data.packet.len);
		if (s0) {
			result -> len = 2;
			if (!buffer_allocate (&result -> buffer, 2,
					      "expr_encode_int16")) {
				log_error ("data: encode_int16: no memory");
				result -> len = 0;
				s0 = 0;
			} else {
				result -> data = &result -> buffer -> data [0];
				putUShort (result -> data, len);
			}
		} else
			result -> len = 0;

#if defined (DEBUG_EXPRESSIONS)
		if (!s0)
			log_info ("data: encode_int16 (NULL) = NULL");
		else
			log_info ("data: encode_int16 (%d) = %s", len,
				  print_hex_2 (result -> len,
					       result -> data, 20));
#endif
		return s0;

	      case expr_encode_int32:
		s0 = evaluate_numeric_expression (&len, packet, options,
						  expr -> data.packet.len);
		if (s0) {
			result -> len = 4;
			if (!buffer_allocate (&result -> buffer, 4,
					      "expr_encode_int32")) {
				log_error ("data: encode_int32: no memory");
				result -> len = 0;
				s0 = 0;
			} else {
				result -> data = &result -> buffer -> data [0];
				putULong (result -> data, len);
			}
		} else
			result -> len = 0;

#if defined (DEBUG_EXPRESSIONS)
		if (!s0)
			log_info ("data: encode_int32 (NULL) = NULL");
		else
			log_info ("data: encode_int32 (%d) = %s", len,
				  print_hex_2 (result -> len,
					       result -> data, 20));
#endif
		return s0;

	      case expr_check:
	      case expr_equal:
	      case expr_and:
	      case expr_or:
	      case expr_not:
	      case expr_match:
	      case expr_known:
		log_error ("Boolean opcode in evaluate_data_expression: %d",
		      expr -> op);
		return 0;

	      case expr_extract_int8:
	      case expr_extract_int16:
	      case expr_extract_int32:
	      case expr_const_int:
		log_error ("Numeric opcode in evaluate_data_expression: %d",
		      expr -> op);
		return 0;
	}

	log_error ("Bogus opcode in evaluate_data_expression: %d", expr -> op);
	return 0;
}	

int evaluate_numeric_expression (result, packet, options, expr)
	unsigned long *result;
	struct packet *packet;
	struct option_state *options;
	struct expression *expr;
{
	struct data_string data;
	int status;

	switch (expr -> op) {
	      case expr_check:
	      case expr_equal:
	      case expr_and:
	      case expr_or:
	      case expr_not:
	      case expr_match:
	      case expr_known:
		log_error ("Boolean opcode in evaluate_numeric_expression: %d",
		      expr -> op);
		return 0;

	      case expr_substring:
	      case expr_suffix:
	      case expr_option:
	      case expr_hardware:
	      case expr_const_data:
	      case expr_packet:
	      case expr_concat:
	      case expr_encapsulate:
	      case expr_host_lookup:
	      case expr_encode_int8:
	      case expr_encode_int16:
	      case expr_encode_int32:
		log_error ("Data opcode in evaluate_numeric_expression: %d",
		      expr -> op);
		return 0;

	      case expr_extract_int8:
		memset (&data, 0, sizeof data);
		status = evaluate_data_expression
			(&data, packet,
			 options, expr -> data.extract_int);
		if (status)
			*result = data.data [0];
#if defined (DEBUG_EXPRESSIONS)
		log_info ("num: extract_int8 (%s) = %s",
		      status ? print_hex_1 (data.len, data.data, 60) : "NULL",
		      status ? print_dec_1 (*result) : "NULL" );
#endif
		if (status)
			data_string_forget (&data, "expr_extract_int8");
		return status;

	      case expr_extract_int16:
		memset (&data, 0, sizeof data);
		status = (evaluate_data_expression
			  (&data, packet, options,
			   expr -> data.extract_int));
		if (status && data.len >= 2)
			*result = getUShort (data.data);
#if defined (DEBUG_EXPRESSIONS)
		log_info ("num: extract_int16 (%s) = %ld",
		      ((status && data.len >= 2) ?
		       print_hex_1 (data.len, data.data, 60) : "NULL"),
		      *result);
#endif
		if (status)
			data_string_forget (&data, "expr_extract_int16");
		return (status && data.len >= 2);

	      case expr_extract_int32:
		memset (&data, 0, sizeof data);
		status = (evaluate_data_expression
			  (&data, packet, options,
			   expr -> data.extract_int));
		if (status && data.len >= 4)
			*result = getULong (data.data);
#if defined (DEBUG_EXPRESSIONS)
		log_info ("num: extract_int32 (%s) = %ld",
		      ((status && data.len >= 4) ?
		       print_hex_1 (data.len, data.data, 60) : "NULL"),
		      *result);
#endif
		if (status)
			data_string_forget (&data, "expr_extract_int32");
		return (status && data.len >= 4);

	      case expr_const_int:
		*result = expr -> data.const_int;
		return 1;
	}

	log_error ("evaluate_numeric_expression: bogus opcode %d", expr -> op);
	return 0;
}

/* Return data hanging off of an option cache structure, or if there
   isn't any, evaluate the expression hanging off of it and return the
   result of that evaluation.   There should never be both an expression
   and a valid data_string. */

int evaluate_option_cache (result, packet, options, oc)
	struct data_string *result;
	struct packet *packet;
	struct option_state *options;
	struct option_cache *oc;
{
	if (oc -> data.len) {
		data_string_copy (result,
				  &oc -> data, "evaluate_option_cache");
		return 1;
	}
	if (!oc -> expression)
		return 0;
	return evaluate_data_expression (result,
					 packet, options, oc -> expression);
}

/* Evaluate an option cache and extract a boolean from the result,
   returning the boolean.   Return false if there is no data. */

int evaluate_boolean_option_cache (packet, options, oc)
	struct packet *packet;
	struct option_state *options;
	struct option_cache *oc;
{
	struct data_string ds;
	int result;

	/* So that we can be called with option_lookup as an argument. */
	if (!oc || !options)
		return 0;
	
	memset (&ds, 0, sizeof ds);
	if (!evaluate_option_cache (&ds, packet, options, oc))
		return 0;

	if (ds.len && ds.data [0])
		result = 1;
	else
		result = 0;
	data_string_forget (&ds, "evaluate_boolean_option_cache");
	return result;
}
		

/* Evaluate a boolean expression and return the result of the evaluation,
   or FALSE if it failed. */

int evaluate_boolean_expression_result (packet, options, expr)
	struct packet *packet;
	struct option_state *options;
	struct expression *expr;
{
	int result;

	/* So that we can be called with option_lookup as an argument. */
	if (!expr)
		return 0;
	
	if (!evaluate_boolean_expression (&result, packet, options, expr))
		return 0;

	return result;
}
		

/* Dereference an expression node, and if the reference count goes to zero,
   dereference any data it refers to, and then free it. */
void expression_dereference (eptr, name)
	struct expression **eptr;
	char *name;
{
	struct expression *expr = *eptr;

	/* Zero the pointer. */
	*eptr = (struct expression *)0;

	/* Decrement the reference count.   If it's nonzero, we're
	   done. */
	if (--(expr -> refcnt) > 0)
		return;
	if (expr -> refcnt < 0) {
		log_error ("expression_dereference: negative refcnt!");
#if defined (POINTER_DEBUG)
		abort ();
#else
		return;
#endif
	}

	/* Dereference subexpressions. */
	switch (expr -> op) {
		/* All the binary operators can be handled the same way. */
	      case expr_equal:
	      case expr_concat:
	      case expr_and:
	      case expr_or:
		if (expr -> data.equal [0])
			expression_dereference (&expr -> data.equal [0], name);
		if (expr -> data.equal [1])
			expression_dereference (&expr -> data.equal [1], name);
		break;

	      case expr_substring:
		if (expr -> data.substring.expr)
			expression_dereference (&expr -> data.substring.expr,
						name);
		if (expr -> data.substring.offset)
			expression_dereference (&expr -> data.substring.offset,
						name);
		if (expr -> data.substring.len)
			expression_dereference (&expr -> data.substring.len,
						name);
		break;

	      case expr_suffix:
		if (expr -> data.suffix.expr)
			expression_dereference (&expr -> data.suffix.expr,
						name);
		if (expr -> data.suffix.len)
			expression_dereference (&expr -> data.suffix.len,
						name);
		break;

	      case expr_not:
		if (expr -> data.not)
			expression_dereference (&expr -> data.not, name);
		break;

	      case expr_packet:
		if (expr -> data.packet.offset)
			expression_dereference (&expr -> data.packet.offset,
						name);
		if (expr -> data.packet.len)
			expression_dereference (&expr -> data.packet.len,
						name);
		break;

	      case expr_extract_int8:
	      case expr_extract_int16:
	      case expr_extract_int32:
		if (expr -> data.extract_int)
			expression_dereference (&expr -> data.extract_int,
						name);
		break;

	      case expr_encode_int8:
	      case expr_encode_int16:
	      case expr_encode_int32:
		if (expr -> data.encode_int)
			expression_dereference (&expr -> data.encode_int,
						name);
		break;

	      case expr_encapsulate:
	      case expr_const_data:
		data_string_forget (&expr -> data.const_data, name);
		break;

	      case expr_host_lookup:
		if (expr -> data.host_lookup)
			dns_host_entry_dereference (&expr -> data.host_lookup,
						    name);
		break;

		/* No subexpressions. */
	      case expr_const_int:
	      case expr_check:
	      case expr_option:
	      case expr_hardware:
	      case expr_exists:
	      case expr_known:
		break;

	      default:
		break;
	}

	free_expression (expr, "expression_dereference");
}

/* Make a copy of the data in data_string, upping the buffer reference
   count if there's a buffer. */

void data_string_copy (dest, src, name)
	struct data_string *dest;
	struct data_string *src;
	char *name;
{
	if (src -> buffer)
		buffer_reference (&dest -> buffer, src -> buffer, name);
	dest -> data = src -> data;
	dest -> terminated = src -> terminated;
	dest -> len = src -> len;
}

/* Release the reference count to a data string's buffer (if any) and
   zero out the other information, yielding the null data string. */

void data_string_forget (data, name)
	struct data_string *data;
	char *name;
{
	if (data -> buffer)
		buffer_dereference (&data -> buffer, name);
	memset (data, 0, sizeof *data);
}

/* Make a copy of the data in data_string, upping the buffer reference
   count if there's a buffer. */

void data_string_truncate (dp, len)
	struct data_string *dp;
	int len;
{
	if (len < dp -> len) {
		dp -> terminated = 0;
		dp -> len = len;
	}
}

int is_boolean_expression (expr)
	struct expression *expr;
{
	return (expr -> op == expr_check ||
		expr -> op == expr_exists ||
		expr -> op == expr_equal ||
		expr -> op == expr_and ||
		expr -> op == expr_or ||
		expr -> op == expr_not);
}

int is_data_expression (expr)
	struct expression *expr;
{
	return (expr -> op == expr_substring ||
		expr -> op == expr_suffix ||
		expr -> op == expr_option ||
		expr -> op == expr_hardware ||
		expr -> op == expr_const_data ||
		expr -> op == expr_packet ||
		expr -> op == expr_concat ||
		expr -> op == expr_encapsulate ||
		expr -> op == expr_encode_int8 ||
		expr -> op == expr_encode_int16 ||
		expr -> op == expr_encode_int32 ||
		expr -> op == expr_host_lookup);
}

int is_numeric_expression (expr)
	struct expression *expr;
{
	return (expr -> op == expr_extract_int8 ||
		expr -> op == expr_extract_int16 ||
		expr -> op == expr_extract_int32 ||
		expr -> op == expr_const_int);
}

static int op_val PROTO ((enum expr_op));

static int op_val (op)
	enum expr_op op;
{
	switch (op) {
	      case expr_none:
	      case expr_match:
	      case expr_check:
	      case expr_substring:
	      case expr_suffix:
	      case expr_concat:
	      case expr_encapsulate:
	      case expr_host_lookup:
	      case expr_not:
	      case expr_option:
	      case expr_hardware:
	      case expr_packet:
	      case expr_const_data:
	      case expr_extract_int8:
	      case expr_extract_int16:
	      case expr_extract_int32:
	      case expr_encode_int8:
	      case expr_encode_int16:
	      case expr_encode_int32:
	      case expr_const_int:
	      case expr_exists:
	      case expr_known:
		return 100;

	      case expr_equal:
		return 3;

	      case expr_and:
		return 1;

	      case expr_or:
		return 2;
	}
	return 100;
}

int op_precedence (op1, op2)
	enum expr_op op1, op2;
{
	int ov1, ov2;

	return op_val (op1) - op_val (op2);
}

enum expression_context op_context (op)
	enum expr_op op;
{
	switch (op) {
	      case expr_none:
	      case expr_match:
	      case expr_check:
	      case expr_substring:
	      case expr_suffix:
	      case expr_concat:
	      case expr_encapsulate:
	      case expr_host_lookup:
	      case expr_not:
	      case expr_option:
	      case expr_hardware:
	      case expr_packet:
	      case expr_const_data:
	      case expr_extract_int8:
	      case expr_extract_int16:
	      case expr_extract_int32:
	      case expr_encode_int8:
	      case expr_encode_int16:
	      case expr_encode_int32:
	      case expr_const_int:
	      case expr_exists:
	      case expr_known:
		return context_any;

	      case expr_equal:
		return context_data;

	      case expr_and:
		return context_boolean;

	      case expr_or:
		return context_boolean;
	}
	return context_any;
}
