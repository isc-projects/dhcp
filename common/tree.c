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
"$Id: tree.c,v 1.67 2000/01/08 01:38:52 mellon Exp $ Copyright (c) 1995, 1996, 1997, 1998 The Internet Software Consortium.  All rights reserved.\n";
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
	unsigned len;
	struct option *option;
	const char *name;
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
		log_error ("%s: can't allocate option cache.", name);
		buffer_dereference (&bp, name);
		return 0;
	}

	(*oc) -> data.len = len;
	(*oc) -> data.data = &bp -> data [0];
	(*oc) -> data.terminated = 0;
	if (data)
		memcpy (&bp -> data [0], data, len);
	(*oc) -> option = option;
	return 1;
}

int make_host_lookup (expr, name)
	struct expression **expr;
	const char *name;
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
	const char *name;
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
	const unsigned char *data;
	unsigned len;
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
			memcpy (nt -> data.const_data.buffer -> data,
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

static int do_host_lookup (result, dns)
	struct data_string *result;
	struct dns_host_entry *dns;
{
	struct hostent *h;
	unsigned i, count;
	unsigned new_len;

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
		memcpy (&dns -> data.buffer -> data [h -> h_length * i],
			h -> h_addr_list [i], (unsigned)(h -> h_length));
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

int evaluate_dns_expression (result, packet, lease, in_options,
			     cfg_options, expr)
	ns_updrec **result;
	struct packet *packet;
	struct lease *lease;
	struct option_state *in_options;
	struct option_state *cfg_options;
	struct expression *expr;
{
	ns_updrec *foo;
	unsigned long ttl = 0;
	char *tname;
	struct data_string name, data;
	int r0, r1, r2, r3;

	if (!result || *result) {
		log_error ("evaluate_dns_expression called with non-null %s",
			   "result pointer");
#if defined (POINTER_DEBUG)
		abort ();
#else
		return 0;
#endif
	}
		
	switch (expr -> op) {
#if defined (NSUPDATE)
	      case expr_ns_add:
		r0 = evaluate_numeric_expression (&ttl, packet, lease,
						  in_options, cfg_options,
						  expr -> data.ns_add.ttl);
		goto nsfinish;

	      case expr_ns_exists:
		ttl = 1;

	      case expr_ns_delete:
	      case expr_ns_not_exists:
		r0 = 1;
	      nsfinish:
		memset (&name, 0, sizeof name);
		r1 = evaluate_data_expression (&name, packet, lease,
					       in_options, cfg_options,
					       expr -> data.ns_add.rrname);
		if (r1) {
			/* The result of the evaluation may or may not
			   be NUL-terminated, but we need it
			   terminated for sure, so we have to allocate
			   a buffer and terminate it. */
			tname = malloc (name.len + 1);
			if (!tname) {
				r2 = 0;
				r1 = 0;
				data_string_forget (&name,
						    "evaluate_dns_expression");
			} else {
				memcpy (tname, name.data, name.len);
				tname [name.len] = 0;
				memset (&data, 0, sizeof data);
				r2 = evaluate_data_expression
					(&data, packet, lease, in_options,
					 cfg_options,
					 expr -> data.ns_add.rrdata);
			}
		} else
			r2 = 0;
		if (r0 && r1 && (r2 || expr -> op != expr_ns_add)) {
		    *result = res_mkupdrec (((expr -> op == expr_ns_add ||
					      expr -> op == expr_ns_delete)
					     ? S_UPDATE : S_PREREQ),
					    tname, expr -> data.ns_add.rrclass,
					    expr -> data.ns_add.rrtype, ttl);
		    if (!*result) {
			  ngood:
			    if (r2) {
				data_string_forget (&data,
						    "evaluate_dns_expression");
				r2 = 0;
			    }
		    } else {
			if (data.len) {
				/* As a special case, if we get exactly
				   four bytes of data, it's an IP address
				   represented as a 32-bit quantity, which
				   is actually what we *should* be getting
				   here.   Because res_mkupdrec is currently
				   broken and expects a dotted quad, convert
				   it.   This should be fixed when the new
				   resolver is merged. */
				if (data.len == 4) {
				    (*result) -> r_data = malloc (16);
				    if (!(*result) -> r_data)
					goto dpngood;
				    sprintf ((*result) -> r_data,
					     "%d.%d.%d.%d",
					     data.data [0], data.data [1],
					     data.data [2], data.data [3]);
				    (*result) -> r_size = 
					    strlen ((*result) -> r_data);
				} else {
				    (*result) -> r_size = data.len;
				    (*result) -> r_data = malloc (data.len);
				    if (!(*result) -> r_data) {
				      dpngood: /* double plus ungood. */
					res_freeupdrec (*result);
					*result = 0;
					goto ngood;
				    }
				    memcpy ((*result) -> r_data,
					    data.data, data.len);
				}
			} else {
				(*result) -> r_data = 0;
				(*result) -> r_size = 0;
			}
			switch (expr -> op) {
			      case expr_ns_add:
				(*result) -> r_opcode = ADD;
				break;
			      case expr_ns_delete:
				(*result) -> r_opcode = DELETE;
				break;
			      case expr_ns_exists:
				(*result) -> r_opcode = YXRRSET;
				break;
			      case expr_ns_not_exists:
				(*result) -> r_opcode = NXRRSET;
				break;

				/* Can't happen, but satisfy gcc. */
			      default:
				break;
			}
		    }
		}
		if (r1) {
			data_string_forget (&name, "evaluate_dns_expression");
			free (tname);
		}
		if (r2)
			data_string_forget (&data, "evaluate_dns_expression");
		/* One flaw in the thinking here: an IP address and an
		   ASCII string both look like data expressions, but
		   for A records, we want an ASCII string, not a
		   binary IP address.  Do I need to turn binary IP
		   addresses into a seperate type?  */
		return r0 && r1 && r2 && *result;

#else
	      case expr_ns_add:
	      case expr_ns_delete:
	      case expr_ns_exists:
	      case expr_ns_not_exists:
		return 0;
#endif
	      case expr_check:
	      case expr_equal:
	      case expr_not_equal:
	      case expr_and:
	      case expr_or:
	      case expr_not:
	      case expr_match:
	      case expr_static:
	      case expr_known:
	      case expr_exists:
	      case expr_variable_exists:
		log_error ("Boolean opcode in evaluate_dns_expression: %d",
		      expr -> op);
		return 0;

	      case expr_none:
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
	      case expr_binary_to_ascii:
	      case expr_reverse:
	      case expr_pick_first_value:
	      case expr_host_decl_name:
	      case expr_config_option:
	      case expr_leased_address:
	      case expr_null:
	      case expr_variable_reference:
		log_error ("Data opcode in evaluate_dns_expression: %d",
		      expr -> op);
		return 0;

	      case expr_extract_int8:
	      case expr_extract_int16:
	      case expr_extract_int32:
	      case expr_const_int:
	      case expr_lease_time:
	      case expr_dns_transaction:
		log_error ("Numeric opcode in evaluate_dns_expression: %d",
		      expr -> op);
		return 0;
	}

	log_error ("Bogus opcode in evaluate_dns_expression: %d",
		   expr -> op);
	return 0;
}

int evaluate_boolean_expression (result, packet, lease, in_options,
				 cfg_options, expr)
	int *result;
	struct packet *packet;
	struct lease *lease;
	struct option_state *in_options;
	struct option_state *cfg_options;
	struct expression *expr;
{
	struct data_string left, right;
	struct data_string rrtype, rrname, rrdata;
	unsigned long ttl;
	int srrtype, srrname, srrdata, sttl;
	int bleft, bright;
	int sleft, sright;
	struct binding *binding;

	switch (expr -> op) {
	      case expr_check:
		*result = check_collection (packet, lease,
					    expr -> data.check);
#if defined (DEBUG_EXPRESSIONS)
		log_debug ("bool: check (%s) returns %s",
		      expr -> data.check -> name, *result ? "true" : "false");
#endif
		return 1;

	      case expr_equal:
	      case expr_not_equal:
		memset (&left, 0, sizeof left);
		sleft = evaluate_data_expression (&left, packet, lease,
						  in_options, cfg_options,
						  expr -> data.equal [0]);
		memset (&right, 0, sizeof right);
		sright = evaluate_data_expression (&right, packet, lease,
						   in_options, cfg_options,
						   expr -> data.equal [1]);
		if (sleft && sright) {
			if (left.len == right.len &&
			    !memcmp (left.data, right.data, left.len))
				*result = expr -> op == expr_equal;
			else
				*result = expr -> op == expr_not_equal;
		}

#if defined (DEBUG_EXPRESSIONS)
		log_debug ("bool: %sequal (%s, %s) = %s",
			   expr -> op == expr_not_equal ? "not" : "",
			   (sleft
			    ? print_hex_1 (left.len, left.data, 30)
			    : "NULL"),
			   (sright
			    ? print_hex_2 (right.len, right.data, 30)
			    : "NULL"),
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
		sleft = evaluate_boolean_expression (&bleft, packet, lease,
						     in_options, cfg_options,
						     expr -> data.and [0]);
		sright = evaluate_boolean_expression (&bright, packet, lease,
						      in_options, cfg_options,
						      expr -> data.and [1]);

#if defined (DEBUG_EXPRESSIONS)
		log_debug ("bool: and (%s, %s) = %s",
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
		sleft = evaluate_boolean_expression (&bleft, packet, lease,
						     in_options, cfg_options,
						     expr -> data.or [0]);
		sright = evaluate_boolean_expression (&bright, packet, lease,
						      in_options, cfg_options,
						      expr -> data.or [1]);
#if defined (DEBUG_EXPRESSIONS)
		log_debug ("bool: or (%s, %s) = %s",
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
		sleft = evaluate_boolean_expression (&bleft, packet, lease,
						     in_options, cfg_options,
						     expr -> data.not);
#if defined (DEBUG_EXPRESSIONS)
		log_debug ("bool: not (%s) = %s",
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
		if (!in_options ||
		    !((*expr -> data.option -> universe -> get_func)
		      (&left, expr -> data.exists -> universe,
		       packet, lease, in_options, cfg_options, in_options,
		       expr -> data.exists -> code)))
			*result = 0;
		else {
			*result = 1;
			data_string_forget (&left,
					    "evaluate_boolean_expression");
		}
#if defined (DEBUG_EXPRESSIONS)
		log_debug ("bool: exists %s.%s = %s",
		      expr -> data.option -> universe -> name,
		      expr -> data.option -> name, *result ? "true" : "false");
#endif
		return 1;

	      case expr_known:
		if (!packet) {
#if defined (DEBUG_EXPRESSIONS)
			log_debug ("bool: known = NULL");
#endif
			return 0;
		}
#if defined (DEBUG_EXPRESSIONS)
		log_debug ("bool: known = %s",
			  packet -> known ? "true" : "false");
#endif
		*result = packet -> known;
		return 1;

	      case expr_static:
		if (!lease || !(lease -> flags & STATIC_LEASE)) {
#if defined (DEBUG_EXPRESSIONS)
			log_debug ("bool: static = false");
#endif
			*result = 0;
			return 1;
		}
#if defined (DEBUG_EXPRESSIONS)
		log_debug ("bool: static = true");
#endif
		*result = 1;
		return 1;

	      case expr_variable_exists:
		for (binding = lease -> bindings; binding;
		     binding = binding -> next) {
			if (!(strcasecmp
			      (lease -> bindings -> name,
			       expr -> data.variable)))
				break;
		}
		if (binding) {
			if (binding -> value.data)
				*result = 1;
			else
				*result = 0;
		} else
			*result = 0;
#if defined (DEBUG_EXPRESSIONS)
		log_debug ("boolean: %s? = %s", expr -> variable,
			   s0 ? "true" : "false";
#endif
		return 1;

	      case expr_none:
	      case expr_match:
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
	      case expr_binary_to_ascii:
	      case expr_reverse:
	      case expr_pick_first_value:
	      case expr_host_decl_name:
	      case expr_config_option:
	      case expr_leased_address:
	      case expr_null:
	      case expr_variable_reference:
		log_error ("Data opcode in evaluate_boolean_expression: %d",
		      expr -> op);
		return 0;

	      case expr_extract_int8:
	      case expr_extract_int16:
	      case expr_extract_int32:
	      case expr_const_int:
	      case expr_lease_time:
	      case expr_dns_transaction:
		log_error ("Numeric opcode in evaluate_boolean_expression: %d",
		      expr -> op);
		return 0;

	      case expr_ns_add:
	      case expr_ns_delete:
	      case expr_ns_exists:
	      case expr_ns_not_exists:
		log_error ("dns opcode in evaluate_boolean_expression: %d",
		      expr -> op);
		return 0;
	}

	log_error ("Bogus opcode in evaluate_boolean_expression: %d",
		   expr -> op);
	return 0;
}

int evaluate_data_expression (result, packet, lease,
			      in_options, cfg_options, expr)
	struct data_string *result;
	struct packet *packet;
	struct lease *lease;
	struct option_state *in_options;
	struct option_state *cfg_options;
	struct expression *expr;
{
	struct data_string data, other;
	unsigned long offset, len, i;
	int s0, s1, s2, s3;
	int status;
	struct binding *binding;
	char *s;

	switch (expr -> op) {
		/* Extract N bytes starting at byte M of a data string. */
	      case expr_substring:
		memset (&data, 0, sizeof data);
		s0 = evaluate_data_expression (&data, packet, lease,
					       in_options, cfg_options,
					       expr -> data.substring.expr);

		/* Evaluate the offset and length. */
		s1 = evaluate_numeric_expression
			(&offset, packet, lease, in_options, cfg_options,
			 expr -> data.substring.offset);
		s2 = evaluate_numeric_expression (&len, packet, lease,
						  in_options, cfg_options,
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
		log_debug ("data: substring (%s, %s, %s) = %s",
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
		s0 = evaluate_data_expression (&data, packet, lease,
					       in_options, cfg_options,
					       expr -> data.suffix.expr);
		/* Evaluate the length. */
		s1 = evaluate_numeric_expression (&len, packet, lease,
						  in_options, cfg_options,
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
		log_debug ("data: suffix (%s, %s) = %s",
		      s0 ? print_hex_1 (data.len, data.data, 30) : "NULL",
		      s1 ? print_dec_1 (len) : "NULL",
		      ((s0 && s1)
		       ? print_hex_2 (result -> len, result -> data, 30)
		       : "NULL"));
#endif
		return s0 && s1;

		/* Extract an option. */
	      case expr_option:
		if (in_options)
			s0 = ((*expr -> data.option -> universe -> get_func)
			      (result, expr -> data.option -> universe,
			       packet, lease,
			       in_options, cfg_options, in_options,
			       expr -> data.option -> code));
		else
			s0 = 0;

#if defined (DEBUG_EXPRESSIONS)
		log_debug ("data: option %s.%s = %s",
		      expr -> data.option -> universe -> name,
		      expr -> data.option -> name,
		      s0 ? print_hex_1 (result -> len, result -> data, 60)
		      : "NULL");
#endif
		return s0;

	      case expr_config_option:
		if (cfg_options)
			s0 = ((*expr -> data.option -> universe -> get_func)
			      (result, expr -> data.option -> universe,
			       packet, lease,
			       in_options, cfg_options, cfg_options,
			       expr -> data.option -> code));
		else
			s0 = 0;

#if defined (DEBUG_EXPRESSIONS)
		log_debug ("data: config-option %s.%s = %s",
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
			result -> buffer -> data [0] = packet -> raw -> htype;
			memcpy (&result -> buffer -> data [1],
				packet -> raw -> chaddr,
				packet -> raw -> hlen);
			result -> terminated = 0;
		} else {
			log_error ("data: hardware: no memory for buffer.");
			return 0;
		}
#if defined (DEBUG_EXPRESSIONS)
		log_debug ("data: hardware = %s",
		      print_hex_1 (result -> len, result -> data, 60));
#endif
		return 1;

		/* Extract part of the raw packet. */
	      case expr_packet:
		if (!packet || !packet -> raw) {
			log_error ("data: packet: raw packet not available");
			return 0;
		}

		s0 = evaluate_numeric_expression (&offset, packet, lease,
						  in_options, cfg_options,
						  expr -> data.packet.offset);
		s1 = evaluate_numeric_expression (&len,
						  packet, lease,
						  in_options, cfg_options,
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
				memcpy (result -> buffer -> data,
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
		log_debug ("data: packet (%ld, %ld) = %s",
		      offset, len,
		      s2 ? print_hex_1 (result -> len,
					result -> data, 60) : NULL);
#endif
		return s2;

		/* The encapsulation of all defined options in an
		   option space... */
	      case expr_encapsulate:
		if (cfg_options)
			s0 = option_space_encapsulate
				(result, packet, lease,
				 in_options, cfg_options,
				 &expr -> data.encapsulate);
		else
			s0 = 0;

#if defined (DEBUG_EXPRESSIONS)
		log_debug ("data: encapsulate (%s) = %s",
			  expr -> data.encapsulate.data,
			  s0 ? print_hex_1 (result -> len,
					    result -> data, 60) : "null");
#endif
		return s0;

		/* Some constant data... */
	      case expr_const_data:
#if defined (DEBUG_EXPRESSIONS)
		log_debug ("data: const = %s",
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
		log_debug ("data: DNS lookup (%s) = %s",
		      expr -> data.host_lookup -> hostname,
		      (s0
		       ? print_dotted_quads (result -> len, result -> data)
		       : "NULL"));
#endif
		return s0;

		/* Concatenation... */
	      case expr_concat:
		memset (&data, 0, sizeof data);
		s0 = evaluate_data_expression (&data, packet, lease,
					       in_options, cfg_options,
					       expr -> data.concat [0]);
		memset (&other, 0, sizeof other);
		s1 = evaluate_data_expression (&other, packet, lease,
					       in_options, cfg_options,
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
			memcpy (result -> buffer -> data, data.data, data.len);
			memcpy (&result -> buffer -> data [data.len],
				other.data, other.len + other.terminated);
		} else if (s0)
			data_string_forget (&data, "expr_concat");
		else if (s1)
			data_string_forget (&other, "expr_concat");
#if defined (DEBUG_EXPRESSIONS)
		log_debug ("data: concat (%s, %s) = %s",
		      s0 ? print_hex_1 (data.len, data.data, 20) : "NULL",
		      s1 ? print_hex_2 (other.len, other.data, 20) : "NULL",
		      ((s0 && s1)
		       ? print_hex_3 (result -> len, result -> data, 30)
		       : "NULL"));
#endif
		return s0 && s1;

	      case expr_encode_int8:
		s0 = evaluate_numeric_expression (&len, packet, lease,
						  in_options, cfg_options,
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
				result -> buffer -> data [0] = len;
			}
		} else
			result -> len = 0;

#if defined (DEBUG_EXPRESSIONS)
		if (!s0)
			log_debug ("data: encode_int8 (NULL) = NULL");
		else
			log_debug ("data: encode_int8 (%ld) = %s", len,
				  print_hex_2 (result -> len,
					       result -> data, 20));
#endif
		return s0;
			
		
	      case expr_encode_int16:
		s0 = evaluate_numeric_expression (&len, packet, lease,
						  in_options, cfg_options,
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
				putUShort (result -> buffer -> data, len);
			}
		} else
			result -> len = 0;

#if defined (DEBUG_EXPRESSIONS)
		if (!s0)
			log_debug ("data: encode_int16 (NULL) = NULL");
		else
			log_debug ("data: encode_int16 (%ld) = %s", len,
				  print_hex_2 (result -> len,
					       result -> data, 20));
#endif
		return s0;

	      case expr_encode_int32:
		s0 = evaluate_numeric_expression (&len, packet, lease,
						  in_options, cfg_options,
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
				putULong (result -> buffer -> data, len);
			}
		} else
			result -> len = 0;

#if defined (DEBUG_EXPRESSIONS)
		if (!s0)
			log_debug ("data: encode_int32 (NULL) = NULL");
		else
			log_debug ("data: encode_int32 (%ld) = %s", len,
				  print_hex_2 (result -> len,
					       result -> data, 20));
#endif
		return s0;

	      case expr_binary_to_ascii:
		/* Evaluate the base (offset) and width (len): */
		s0 = evaluate_numeric_expression
			(&offset, packet, lease, in_options, cfg_options,
			 expr -> data.b2a.base);
		s1 = evaluate_numeric_expression (&len, packet, lease,
						  in_options, cfg_options,
						  expr -> data.b2a.width);

		/* Evaluate the seperator string. */
		memset (&data, 0, sizeof data);
		s2 = evaluate_data_expression (&data, packet, lease,
					       in_options, cfg_options,
					       expr -> data.b2a.seperator);

		/* Evaluate the data to be converted. */
		memset (&other, 0, sizeof other);
		s3 = evaluate_data_expression (&other, packet, lease,
					       in_options, cfg_options,
					       expr -> data.b2a.buffer);

		if (s0 && s1 && s2 && s3) {
			unsigned buflen, i;

			if (len != 8 && len != 16 && len != 32) {
				log_info ("binary_to_ascii: %s %ld!",
					  "invalid width", len);
				goto b2a_out;
			}
			len /= 8;

			/* The buffer must be a multiple of the number's
			   width. */
			if (other.len % len) {
				log_info ("binary-to-ascii: %s %d %s %ld!",
					  "length of buffer", other.len,
					  "not a multiple of width", len);
				status = 0;
				goto b2a_out;
			}

			/* Count the width of the output. */
			buflen = 0;
			for (i = 0; i < other.len; i += len) {
				if (len == 1) {
					if (offset == 8) {
						if (other.data [i] < 8)
							buflen++;
						else if (other.data [i] < 64)
							buflen += 2;
						else
							buflen += 3;
					} else if (offset == 10) {
						if (other.data [i] < 10)
							buflen++;
						else if (other.data [i] < 100)
							buflen += 2;
						else
							buflen += 3;
					} else if (offset == 10) {
						if (other.data [i] < 16)
							buflen++;
						else
							buflen += 2;
					} else
						buflen += (converted_length
							   (&other.data [i],
							    offset, 1));
				} else
					buflen += (converted_length
						   (&other.data [i],
						    offset, len));
				if (i + len != other.len)
					buflen += data.len;
			}

			if (!buffer_allocate (&result -> buffer, buflen + 1,
					      "binary-to-ascii")) {
				log_error ("data: binary-to-ascii: no memory");
				status = 0;
				goto b2a_out;
			}
			result -> data = &result -> buffer -> data [0];
			result -> len = buflen;
			result -> terminated = 1;

			buflen = 0;
			for (i = 0; i < other.len; i += len) {
				buflen += (binary_to_ascii
					   (&result -> buffer -> data [buflen],
					    &other.data [i], offset, len));
				if (i + len != other.len) {
					memcpy (&result ->
						buffer -> data [buflen],
						data.data, data.len);
					buflen += data.len;
				}
			}
			/* NUL terminate. */
			result -> buffer -> data [buflen] = 0;
			status = 1;
		} else
			status = 0;

	      b2a_out:
#if defined (DEBUG_EXPRESSIONS)
		log_debug ("data: binary-to-ascii (%s, %s, %s, %s) = %s",
		      s0 ? print_dec_1 (offset) : "NULL",
		      s1 ? print_dec_2 (len) : "NULL",
		      s2 ? print_hex_1 (data.len, data.data, 30) : "NULL",
		      s3 ? print_hex_2 (other.len, other.data, 30) : "NULL",
		      (status ? print_hex_3 (result -> len, result -> data, 30)
		          : "NULL"));
#endif
		if (s2)
			data_string_forget (&data, "binary-to-ascii");
		if (s3)
			data_string_forget (&other, "binary-to-ascii");
		if (status)
			return 1;
		return 0;

	      case expr_reverse:
		/* Evaluate the width (len): */
		s0 = evaluate_numeric_expression
			(&len, packet, lease, in_options, cfg_options,
			 expr -> data.reverse.width);

		/* Evaluate the data. */
		memset (&data, 0, sizeof data);
		s1 = evaluate_data_expression (&data, packet, lease,
					       in_options, cfg_options,
					       expr -> data.reverse.buffer);

		if (s0 && s1) {
			char *upper;
			int i;

			/* The buffer must be a multiple of the number's
			   width. */
			if (other.len % len) {
				log_info ("reverse: %s %d %s %ld!",
					  "length of buffer", other.len,
					  "not a multiple of width", len);
				status = 0;
				goto reverse_out;
			}

			/* XXX reverse in place?   I don't think we can. */
			if (!buffer_allocate (&result -> buffer, data.len,
					      "reverse")) {
				log_error ("data: reverse: no memory");
				status = 0;
				goto reverse_out;
			}
			result -> data = &result -> buffer -> data [0];
			result -> len = data.len;
			result -> terminated = 0;

			for (i = 0; i < data.len; i += len) {
				memcpy (&result -> buffer -> data [i],
					&data.data [data.len - i - len], len);
			}
			status = 1;
		} else
			status = 0;

	      reverse_out:
#if defined (DEBUG_EXPRESSIONS)
		log_debug ("data: reverse (%s, %s) = %s",
		      s0 ? print_dec_1 (len) : "NULL",
		      s1 ? print_hex_1 (data.len, data.data, 30) : "NULL",
		      (status ? print_hex_3 (result -> len, result -> data, 30)
		          : "NULL"));
#endif
		if (s0)
			data_string_forget (&data, "evaluate_data_expression");
		if (status)
			return 1;
		return 0;

	      case expr_leased_address:
		if (!lease) {
			log_error ("data: leased_address: not available");
			return 0;
		}
		result -> len = lease -> ip_addr.len;
		if (buffer_allocate (&result -> buffer, result -> len,
				     "leased-address")) {
			result -> data = &result -> buffer -> data [0];
			memcpy (&result -> buffer -> data [0],
				lease -> ip_addr.iabuf, lease -> ip_addr.len);
			result -> terminated = 0;
		} else {
			log_error ("data: leased-address: no memory.");
			return 0;
		}
#if defined (DEBUG_EXPRESSIONS)
		log_debug ("data: leased-address = %s",
		      print_hex_1 (result -> len, result -> data, 60));
#endif
		return 1;

	      case expr_pick_first_value:
		memset (&data, 0, sizeof data);
		if ((evaluate_data_expression
		     (result, packet, lease, in_options, cfg_options,
		      expr -> data.pick_first_value.car))) {
#if defined (DEBUG_EXPRESSIONS)
			log_debug ("data: pick_first_value (%s, ???)",
				   print_hex_1 (result -> len,
						result -> data, 40));
#endif
			return 1;
		}

		if (expr -> data.pick_first_value.cdr &&
		    (evaluate_data_expression
		     (result, packet, lease, in_options, cfg_options,
		      expr -> data.pick_first_value.cdr))) {
#if defined (DEBUG_EXPRESSIONS)
			log_debug ("data: pick_first_value (NULL, %s)",
				   print_hex_1 (result -> len,
						result -> data, 40));
#endif
			return 1;
		}

#if defined (DEBUG_EXPRESSIONS)
		log_debug ("data: pick_first_value (NULL, NULL) = NULL");
#endif
		return 0;

	      case expr_host_decl_name:
		if (!lease || !lease -> host) {
			log_error ("data: host_decl_name: not available");
			return 0;
		}
		result -> len = strlen (lease -> host -> name);
		if (buffer_allocate (&result -> buffer, result -> len + 1,
				     "host-decl-name")) {
			result -> data = &result -> buffer -> data [0];
			strcpy ((char *)&result -> buffer -> data [0],
				lease -> host -> name);
			result -> terminated = 1;
		} else {
			log_error ("data: host-decl-name: no memory.");
			return 0;
		}
#if defined (DEBUG_EXPRESSIONS)
		log_debug ("data: host-decl-name = %s", lease -> host -> name);
#endif
		return 1;

	      case expr_null:
#if defined (DEBUG_EXPRESSIONS)
		log_debug ("data: null = NULL");
#endif
		return 0;

	      case expr_variable_reference:
		for (binding = lease -> bindings; binding;
		     binding = binding -> next) {
			if (!(strcasecmp (lease -> bindings -> name,
					  expr -> data.variable)))
				break;
		}
		if (binding) {
			if (binding -> value.data) {
				data_string_copy (result, &binding -> value,
						  "variable-reference");
				s0 = 1;
			} else
				s0 = 0;
		} else
			s0 = 0;
#if defined (DEBUG_EXPRESSIONS)
		log_debug ("data: %s = %s", expr -> variable,
			   s0 ? print_hex_1 (result -> len,
					     result -> data, 50);
#endif
		return s0;

	      case expr_check:
	      case expr_equal:
	      case expr_not_equal:
	      case expr_and:
	      case expr_or:
	      case expr_not:
	      case expr_match:
	      case expr_static:
	      case expr_known:
	      case expr_none:
	      case expr_exists:
	      case expr_variable_exists:
		log_error ("Boolean opcode in evaluate_data_expression: %d",
		      expr -> op);
		return 0;

	      case expr_extract_int8:
	      case expr_extract_int16:
	      case expr_extract_int32:
	      case expr_const_int:
	      case expr_lease_time:
	      case expr_dns_transaction:
		log_error ("Numeric opcode in evaluate_data_expression: %d",
		      expr -> op);
		return 0;

	      case expr_ns_add:
	      case expr_ns_delete:
	      case expr_ns_exists:
	      case expr_ns_not_exists:
		log_error ("dns update opcode in evaluate_data_expression: %d",
		      expr -> op);
		return 0;
	}

	log_error ("Bogus opcode in evaluate_data_expression: %d", expr -> op);
	return 0;
}	

int evaluate_numeric_expression (result, packet, lease,
				 in_options, cfg_options, expr)
	unsigned long *result;
	struct packet *packet;
	struct lease *lease;
	struct option_state *in_options;
	struct option_state *cfg_options;
	struct expression *expr;
{
	struct data_string data;
	int status;
	ns_updrec *nut;
	static struct __res_state res;
	ns_updque uq;
	static int inited;
	struct expression *cur, *next;

	switch (expr -> op) {
	      case expr_check:
	      case expr_equal:
	      case expr_not_equal:
	      case expr_and:
	      case expr_or:
	      case expr_not:
	      case expr_match:
	      case expr_static:
	      case expr_known:
	      case expr_none:
	      case expr_exists:
	      case expr_variable_exists:
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
	      case expr_binary_to_ascii:
	      case expr_reverse:
	      case expr_pick_first_value:
	      case expr_host_decl_name:
	      case expr_config_option:
	      case expr_leased_address:
	      case expr_null:
	      case expr_variable_reference:
		log_error ("Data opcode in evaluate_numeric_expression: %d",
		      expr -> op);
		return 0;

	      case expr_extract_int8:
		memset (&data, 0, sizeof data);
		status = evaluate_data_expression
			(&data, packet, lease, in_options, cfg_options,
			 expr -> data.extract_int);
		if (status)
			*result = data.data [0];
#if defined (DEBUG_EXPRESSIONS)
		log_debug ("num: extract_int8 (%s) = %s",
		      status ? print_hex_1 (data.len, data.data, 60) : "NULL",
		      status ? print_dec_1 (*result) : "NULL" );
#endif
		if (status)
			data_string_forget (&data, "expr_extract_int8");
		return status;

	      case expr_extract_int16:
		memset (&data, 0, sizeof data);
		status = (evaluate_data_expression
			  (&data, packet, lease, in_options, cfg_options,
			   expr -> data.extract_int));
		if (status && data.len >= 2)
			*result = getUShort (data.data);
#if defined (DEBUG_EXPRESSIONS)
		log_debug ("num: extract_int16 (%s) = %ld",
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
			  (&data, packet, lease, in_options, cfg_options,
			   expr -> data.extract_int));
		if (status && data.len >= 4)
			*result = getULong (data.data);
#if defined (DEBUG_EXPRESSIONS)
		log_debug ("num: extract_int32 (%s) = %ld",
		      ((status && data.len >= 4) ?
		       print_hex_1 (data.len, data.data, 60) : "NULL"),
		      *result);
#endif
		if (status)
			data_string_forget (&data, "expr_extract_int32");
		return (status && data.len >= 4);

	      case expr_const_int:
		*result = expr -> data.const_int;
#if defined (DEBUG_EXPRESSIONS)
		log_debug ("number: CONSTANT = %ld", *result);
#endif
		return 1;

	      case expr_lease_time:
		if (!lease) {
			log_error ("data: leased_lease: not available");
			return 0;
		}
		if (lease -> ends < cur_time) {
			log_error ("%s %lu when it is now %lu",
				   "data: lease_time: lease ends at",
				   lease -> ends, cur_time);
			return 0;
		}
		*result = lease -> ends - cur_time;
#if defined (DEBUG_EXPRESSIONS)
		log_debug ("number: lease-time = (%lu - %lu) = %ld",
			   lease -> ends,
			   cur_time, *result);
#endif
		return 1;
 
	      case expr_dns_transaction:
#if !defined (NSUPDATE)
		return 0;
#else
		if (!inited) {
			res_ninit (&res);
			inited = 1;
		}
		INIT_LIST (uq);
		cur = expr;
		do {
		    next = cur -> data.dns_transaction.cdr;
		    nut = 0;
		    status = (evaluate_dns_expression
			      (&nut, packet, lease, in_options, cfg_options,
			       cur -> data.dns_transaction.car));
		    if (!status)
			    goto dns_bad;
		    APPEND (uq, nut, r_link);
		    cur = next;
		} while (next);

		/* Do the update and record the error code, if there was
		   an error; otherwise set it to NOERROR. */
		if (res_nupdate (&res, HEAD (uq), NULL))
			*result = NOERROR;
		else
			*result = res.res_h_errno;
		status = 1;

		print_dns_status ((int)*result, &uq);

	      dns_bad:
		while (!EMPTY (uq)) {
			ns_updrec *tmp = HEAD (uq);
			UNLINK (uq, tmp, r_link);
			if (tmp -> r_data)
				dfree (tmp -> r_data,
				       "evaluate_numeric_expression");
			res_freeupdrec (tmp);
		}
		return status;
#endif /* NSUPDATE */

	      case expr_ns_add:
	      case expr_ns_delete:
	      case expr_ns_exists:
	      case expr_ns_not_exists:
		log_error ("dns opcode in evaluate_numeric_expression: %d",
		      expr -> op);
		return 0;
	}

	log_error ("evaluate_numeric_expression: bogus opcode %d", expr -> op);
	return 0;
}

/* Return data hanging off of an option cache structure, or if there
   isn't any, evaluate the expression hanging off of it and return the
   result of that evaluation.   There should never be both an expression
   and a valid data_string. */

int evaluate_option_cache (result, packet, lease, in_options, cfg_options, oc)
	struct data_string *result;
	struct packet *packet;
	struct lease *lease;
	struct option_state *in_options;
	struct option_state *cfg_options;
	struct option_cache *oc;
{
	if (oc -> data.len) {
		data_string_copy (result,
				  &oc -> data, "evaluate_option_cache");
		return 1;
	}
	if (!oc -> expression)
		return 0;
	return evaluate_data_expression (result, packet, lease, in_options,
					 cfg_options,
					 oc -> expression);
}

/* Evaluate an option cache and extract a boolean from the result,
   returning the boolean.   Return false if there is no data. */

int evaluate_boolean_option_cache (ignorep,
				   packet, lease, in_options, cfg_options, oc)
	int *ignorep;
	struct packet *packet;
	struct lease *lease;
	struct option_state *in_options;
	struct option_state *cfg_options;
	struct option_cache *oc;
{
	struct data_string ds;
	int result;

	/* So that we can be called with option_lookup as an argument. */
	if (!oc || !in_options)
		return 0;
	
	memset (&ds, 0, sizeof ds);
	if (!evaluate_option_cache (&ds, packet, lease,
				    in_options, cfg_options, oc))
		return 0;

	if (ds.len) {
		result = ds.data [0];
		if (result == 2) {
			result = 0;
			*ignorep = 1;
		} else
			*ignorep = 0;
	} else
		result = 0;
	data_string_forget (&ds, "evaluate_boolean_option_cache");
	return result;
}
		

/* Evaluate a boolean expression and return the result of the evaluation,
   or FALSE if it failed. */

int evaluate_boolean_expression_result (ignorep, packet, lease,
					in_options, cfg_options, expr)
	int *ignorep;
	struct packet *packet;
	struct lease *lease;
	struct option_state *in_options;
	struct option_state *cfg_options;
	struct expression *expr;
{
	int result;

	/* So that we can be called with option_lookup as an argument. */
	if (!expr)
		return 0;
	
	if (!evaluate_boolean_expression (&result, packet, lease,
					  in_options, cfg_options, expr))
		return 0;

	if (result == 2) {
		*ignorep = 1;
		result = 0;
	} else
		*ignorep = 0;
	return result;
}
		

/* Dereference an expression node, and if the reference count goes to zero,
   dereference any data it refers to, and then free it. */
void expression_dereference (eptr, name)
	struct expression **eptr;
	const char *name;
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
	      case expr_not_equal:
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

	      case expr_binary_to_ascii:
		if (expr -> data.b2a.base)
			expression_dereference (&expr -> data.b2a.base, name);
		if (expr -> data.b2a.width)
			expression_dereference (&expr -> data.b2a.width, name);
		if (expr -> data.b2a.seperator)
			expression_dereference (&expr -> data.b2a.seperator,
						name);
		if (expr -> data.b2a.buffer)
			expression_dereference (&expr -> data.b2a.buffer,
						name);
		break;

	      case expr_pick_first_value:
		if (expr -> data.pick_first_value.car)
			expression_dereference
				(&expr -> data.pick_first_value.car, name);
		if (expr -> data.pick_first_value.cdr)
			expression_dereference
				(&expr -> data.pick_first_value.cdr, name);
		break;

	      case expr_reverse:
		if (expr -> data.reverse.width)
			expression_dereference (&expr -> data.reverse.width,
						name);
		if (expr -> data.reverse.buffer)
			expression_dereference
				(&expr -> data.reverse.buffer, name);
		break;

	      case expr_dns_transaction:
		if (expr -> data.dns_transaction.car)
			expression_dereference
				(&expr -> data.dns_transaction.car, name);
		if (expr -> data.dns_transaction.cdr)
			expression_dereference
				(&expr -> data.dns_transaction.cdr, name);
		break;

	      case expr_ns_add:
		if (expr -> data.ns_add.rrname)
		    expression_dereference (&expr -> data.ns_add.rrname,
					    name);
		if (expr -> data.ns_add.rrdata)
		    expression_dereference (&expr -> data.ns_add.rrdata,
					    name);
		if (expr -> data.ns_add.ttl)
		    expression_dereference (&expr -> data.ns_add.ttl,
					    name);
		break;

	      case expr_ns_delete:
	      case expr_ns_exists:
	      case expr_ns_not_exists:
		if (expr -> data.ns_delete.rrname)
		    expression_dereference (&expr -> data.ns_delete.rrname,
					    name);
		if (expr -> data.ns_delete.rrdata)
		    expression_dereference (&expr -> data.ns_delete.rrdata,
					    name);
		break;

	      case expr_variable_reference:
	      case expr_variable_exists:
		if (expr -> data.variable)
			dfree (expr -> data.variable, name);
		break;

		/* No subexpressions. */
	      case expr_leased_address:
	      case expr_lease_time:
	      case expr_const_int:
	      case expr_check:
	      case expr_option:
	      case expr_hardware:
	      case expr_exists:
	      case expr_known:
	      case expr_null:
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
	const char *name;
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
	const char *name;
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

int is_dns_expression (expr)
	struct expression *expr;
{
      return (expr -> op == expr_ns_add ||
	      expr -> op == expr_ns_delete ||
	      expr -> op == expr_ns_exists ||
	      expr -> op == expr_ns_not_exists);
}

int is_boolean_expression (expr)
	struct expression *expr;
{
	return (expr -> op == expr_check ||
		expr -> op == expr_exists ||
		expr -> op == expr_variable_exists ||
		expr -> op == expr_equal ||
		expr -> op == expr_not_equal ||
		expr -> op == expr_and ||
		expr -> op == expr_or ||
		expr -> op == expr_not ||
		expr -> op == expr_known ||
		expr -> op == expr_static);
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
		expr -> op == expr_host_lookup ||
		expr -> op == expr_binary_to_ascii ||
		expr -> op == expr_reverse ||
		expr -> op == expr_pick_first_value ||
		expr -> op == expr_host_decl_name ||
		expr -> op == expr_leased_address ||
		expr -> op == expr_config_option ||
		expr -> op == expr_null ||
		expr -> op == expr_variable_reference);
}

int is_numeric_expression (expr)
	struct expression *expr;
{
	return (expr -> op == expr_extract_int8 ||
		expr -> op == expr_extract_int16 ||
		expr -> op == expr_extract_int32 ||
		expr -> op == expr_const_int ||
		expr -> op == expr_lease_time ||
		expr -> op == expr_dns_transaction);
}

int is_compound_expression (expr)
	struct expression *expr;
{
	return (expr -> op == expr_ns_add ||
		expr -> op == expr_ns_delete ||
		expr -> op == expr_ns_exists ||
		expr -> op == expr_ns_not_exists ||
		expr -> op == expr_substring ||
		expr -> op == expr_suffix ||
		expr -> op == expr_option ||
		expr -> op == expr_concat ||
		expr -> op == expr_encode_int8 ||
		expr -> op == expr_encode_int16 ||
		expr -> op == expr_encode_int32 ||
		expr -> op == expr_binary_to_ascii ||
		expr -> op == expr_reverse ||
		expr -> op == expr_pick_first_value ||
		expr -> op == expr_config_option ||
		expr -> op == expr_extract_int8 ||
		expr -> op == expr_extract_int16 ||
		expr -> op == expr_extract_int32 ||
		expr -> op == expr_dns_transaction);
}

static int op_val PROTO ((enum expr_op));

static int op_val (op)
	enum expr_op op;
{
	switch (op) {
	      case expr_none:
	      case expr_match:
	      case expr_static:
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
	      case expr_variable_exists:
	      case expr_known:
	      case expr_binary_to_ascii:
	      case expr_reverse:
	      case expr_pick_first_value:
	      case expr_host_decl_name:
	      case expr_config_option:
	      case expr_leased_address:
	      case expr_lease_time:
	      case expr_dns_transaction:
	      case expr_null:
	      case expr_variable_reference:
	      case expr_ns_add:
	      case expr_ns_delete:
	      case expr_ns_exists:
	      case expr_ns_not_exists:
		return 100;

	      case expr_equal:
	      case expr_not_equal:
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
/* XXX Why aren't these specific? */
	      case expr_none:
	      case expr_match:
	      case expr_static:
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
	      case expr_variable_exists:
	      case expr_known:
	      case expr_binary_to_ascii:
	      case expr_reverse:
	      case expr_pick_first_value:
	      case expr_host_decl_name:
	      case expr_config_option:
	      case expr_leased_address:
	      case expr_lease_time:
	      case expr_null:
	      case expr_variable_reference:
	      case expr_ns_add:
	      case expr_ns_delete:
	      case expr_ns_exists:
	      case expr_ns_not_exists:
	      case expr_dns_transaction:
		return context_any;

	      case expr_equal:
	      case expr_not_equal:
		return context_data;

	      case expr_and:
		return context_boolean;

	      case expr_or:
		return context_boolean;
	}
	return context_any;
}

int write_expression (file, expr, col, indent, firstp)
	FILE *file;
	struct expression *expr;
	int col;
	int indent;
	int firstp;
{
	struct expression *e;
	const char *s;
	char obuf [65];
	int scol;
	int width;

	/* If this promises to be a fat expression, start a new line. */
	if (!firstp && is_compound_expression (expr)) {
		indent_spaces (file, indent);
		col = indent;
	}

	switch (expr -> op) {
	      case expr_none:
		col = token_print_indent (file, col, indent, "", "", "null");
		break;
		
	      case expr_check:
		col = token_print_indent (file, col, indent, "", "", "check");
		col = token_print_indent_concat (file, col, indent,
						 " ", "", "\"",
						 expr -> data.check -> name,
						 "\"", (char *)0);
		break;

	      case expr_not_equal:
		s = "!=";
		goto binary;

	      case expr_equal:
		s = "=";
	      binary:
		col = write_expression (file, expr -> data.equal [0],
					col, indent, 1);
		col = token_print_indent (file, col, indent, " ", " ", s);
		col = write_expression (file, expr -> data.equal [1],
					col, indent + 2, 0);
		break;

	      case expr_substring:
		col = token_print_indent (file, col, indent, "", "",
					  "substring");
		col = token_print_indent (file, col, indent, " ", "", "(");
		scol = col;
		col = write_expression (file, expr -> data.substring.expr,
					col, scol, 1);
		col = token_print_indent (file, col, indent, "", " ", ",");
		col = write_expression (file, expr -> data.substring.offset,
					col, indent, 0);
		col = token_print_indent (file, col, scol, "", " ", ",");
		col = write_expression (file, expr -> data.substring.len,
					col, scol, 0);
		col = token_print_indent (file, col, indent, "", "", ")");
		break;

	      case expr_suffix:
		col = token_print_indent (file, col, indent, "", "", "suffix");
		col = token_print_indent (file, col, indent, " ", "", "(");
		scol = col;
		col = write_expression (file, expr -> data.suffix.expr,
					col, scol, 1);
		col = token_print_indent (file, col, scol, "", " ", ",");
		col = write_expression (file, expr -> data.suffix.len,
					col, scol, 0);
		col = token_print_indent (file, col, indent, "", "", ")");
		break;

	      case expr_concat:
		e = expr;
		col = token_print_indent (file, col, indent, "", "",
					  "concat");
		col = token_print_indent (file, col, indent, " ", "", "(");
		scol = col;
		firstp = 1;
	      concat_again:
		col = write_expression (file, e -> data.concat [0],
					col, scol, firstp);
		firstp = 0;
		if (!e -> data.concat [1])
			goto no_concat_cdr;
		col = token_print_indent (file, col, scol, "", " ", ",");
		if (e -> data.concat [1] -> op == expr_concat) {
			e = e -> data.concat [1];
			goto concat_again;
		}
		col = write_expression (file, e -> data.concat [1],
					col, scol, 0);
	      no_concat_cdr:
		col = token_print_indent (file, col, indent, "", "", ")");
		break;

	      case expr_host_lookup:
		col = token_print_indent (file, col, indent, "", "",
					  "gethostbyname");
		col = token_print_indent (file, col, indent, " ", "", "(");
		col = token_print_indent_concat
			(file, col, indent, "", "",
			 "\"", expr -> data.host_lookup -> hostname, "\"",
			 (char *)0);
		col = token_print_indent (file, col, indent, "", "", ")");
		break;

	      case expr_and:
		s = "and";
		goto binary;

	      case expr_or:
		s = "or";
		goto binary;

	      case expr_not:
		col = token_print_indent (file, col, indent, "", " ", "not");
		col = write_expression (file,
					expr -> data.not, col, indent + 2, 1);
		break;

	      case expr_option:
		s = "option";

	      print_option_name:
		col = token_print_indent (file, col, indent, "", "", s);

		if (expr -> data.option -> universe != &dhcp_universe) {
			col = token_print_indent (file, col, indent,
						  " ", "",
						  (expr -> data.option -> 
						   universe -> name));
			col = token_print_indent (file, col, indent, "", "",
						  ".");
			col = token_print_indent (file, col, indent, "", "",
						  expr -> data.option -> name);
		} else {
			col = token_print_indent (file, col, indent, " ", "",
						  expr -> data.option -> name);
		}
		break;

	      case expr_hardware:	
		col = token_print_indent (file, col, indent, "", "",
					  "hardware");
		break;

	      case expr_packet:
		col = token_print_indent (file, col, indent, "", "",
					  "packet");
		col = token_print_indent (file, col, indent, " ", "", "(");
		scol = col;
		col = write_expression (file, expr -> data.packet.offset,
					col, indent, 1);
		col = token_print_indent (file, col, scol, "", " ", ",");
		col = write_expression (file, expr -> data.packet.len,
					col, scol, 0);
		col = token_print_indent (file, col, indent, "", "", ")");
		break;

	      case expr_const_data:
		col = token_indent_data_string (file, col, indent, "", "",
						&expr -> data.const_data);
		break;

	      case expr_extract_int8:
		width = 8;
	      extract_int:
		col = token_print_indent (file, col, indent, "", "",
					  "extract-int");
		col = token_print_indent (file, col, indent, " ", "", "(");
		scol = col;
		col = write_expression (file, expr -> data.extract_int,
					col, indent, 1);
		col = token_print_indent (file, col, scol, "", " ", ",");
		sprintf (obuf, "%d", width);
		col = token_print_indent (file, col, scol, " ", "", obuf);
		col = token_print_indent (file, col, indent, "", "", ")");
		break;

	      case expr_extract_int16:
		width = 16;
		goto extract_int;

	      case expr_extract_int32:
		width = 32;
		goto extract_int;

	      case expr_encode_int8:
		width = 8;
	      encode_int:
		col = token_print_indent (file, col, indent, "", "",
					  "encode-int");
		col = token_print_indent (file, col, indent, " ", "", "(");
		scol = col;
		col = write_expression (file, expr -> data.extract_int,
					col, indent, 1);
		col = token_print_indent (file, col, scol, "", " ", ",");
		sprintf (obuf, "%d", width);
		col = token_print_indent (file, col, scol, " ", "", obuf);
		col = token_print_indent (file, col, indent, "", "",
					  ")");
		break;

	      case expr_encode_int16:
		width = 16;
		goto encode_int;

	      case expr_encode_int32:
		width = 32;
		goto encode_int;

	      case expr_const_int:
		sprintf (obuf, "%lu", expr -> data.const_int);
		col = token_print_indent (file, col, indent, "", "", obuf);
		break;

	      case expr_exists:
		s = "exists";
		goto print_option_name;

	      case expr_encapsulate:
		col = token_print_indent (file, col, indent, "", "",
					  "encapsulate");
		col = token_indent_data_string (file, col, indent, " ", "",
						&expr -> data.encapsulate);
		break;

	      case expr_known:
		col = token_print_indent (file, col, indent, "", "", "known");
		break;

	      case expr_reverse:
		col = token_print_indent (file, col, indent, "", "",
					  "reverse");
		col = token_print_indent (file, col, indent, " ", "", "(");
		scol = col;
		col = write_expression (file, expr -> data.reverse.width,
					col, scol, 1);
		col = token_print_indent (file, col, scol, "", " ", ",");
		col = write_expression (file, expr -> data.reverse.buffer,
					col, scol, 0);
		col = token_print_indent (file, col, indent, "", "",
					  ")");
		break;

	      case expr_leased_address:
		col = token_print_indent (file, col, indent, "", "",
					  "leased-address");
		break;

	      case expr_binary_to_ascii:
		col = token_print_indent (file, col, indent, "", "",
					  "binary-to-ascii");
		col = token_print_indent (file, col, indent, " ", "",
					  "(");
		scol = col;
		col = write_expression (file, expr -> data.b2a.base,
					col, scol, 1);
		col = token_print_indent (file, col, scol, "", " ",
					  ",");
		col = write_expression (file, expr -> data.b2a.width,
					col, scol, 0);
		col = token_print_indent (file, col, scol, "", " ",
					  ",");
		col = write_expression (file, expr -> data.b2a.seperator,
					col, scol, 0);
		col = token_print_indent (file, col, scol, "", " ",
					  ",");
		col = write_expression (file, expr -> data.b2a.buffer,
					col, scol, 0);
		col = token_print_indent (file, col, indent, "", "",
					  ")");
		break;

	      case expr_config_option:
		s = "config-option";
		goto print_option_name;

	      case expr_host_decl_name:
		col = token_print_indent (file, col, indent, "", "",
					  "host-decl-name");
		break;

	      case expr_pick_first_value:
		e = expr;
		col = token_print_indent (file, col, indent, "", "",
					  "concat");
		col = token_print_indent (file, col, indent, " ", "",
					  "(");
		scol = col;
		firstp = 1;
	      pick_again:
		col = write_expression (file,
					e -> data.pick_first_value.car,
					col, scol, firstp);
		firstp = 0;
		/* We're being very lisp-like right now - instead of
                   representing this expression as (first middle . last) we're
                   representing it as (first middle last), which means that the
                   tail cdr is always nil.  Apologies to non-wisp-lizards - may
                   this obscure way of describing the problem motivate you to
                   learn more about the one true computing language. */
		if (!e -> data.pick_first_value.cdr)
			goto no_pick_cdr;
		col = token_print_indent (file, col, scol, "", " ",
					  ",");
		if (e -> data.pick_first_value.cdr -> op ==
		    expr_pick_first_value) {
			e = e -> data.pick_first_value.cdr;
			goto pick_again;
		}
		col = write_expression (file,
					e -> data.pick_first_value.cdr,
					col, scol, 0);
	      no_pick_cdr:
		col = token_print_indent (file, col, indent, "", "",
					  ")");
		break;

	      case expr_lease_time:
		col = token_print_indent (file, col, indent, "", "",
					  "lease-time");
		break;

	      case expr_dns_transaction:
		col = token_print_indent (file, col, indent, "", "",
					  "ns-update");
		col = token_print_indent (file, col, indent, " ", "",
					  "(");
		scol = 0;
		for (e = expr;
		     e && e -> op == expr_dns_transaction;
		     e = e -> data.dns_transaction.cdr) {
			if (!scol) {
				scol = col;
				firstp = 1;
			} else
				firstp = 0;
			col = write_expression (file,
						e -> data.dns_transaction.car,
						col, scol, firstp);
			if (e -> data.dns_transaction.cdr)
				col = token_print_indent (file, col, scol,
							  "", " ", ",");
		}
		if (e)
			col = write_expression (file, e, col, scol, 0);
		col = token_print_indent (file, col, indent, "", "", ")");
		break;

	      case expr_ns_add:
		col = token_print_indent (file, col, indent, "", "",
					  "update");
		col = token_print_indent (file, col, indent, " ", "",
					  "(");
		scol = col;
		sprintf (obuf, "%d", expr -> data.ns_add.rrclass);
		col = token_print_indent (file, col, scol, "", "", obuf);
		col = token_print_indent (file, col, scol, "", " ",
					  ",");
		sprintf (obuf, "%d", expr -> data.ns_add.rrtype);
		col = token_print_indent (file, col, scol, "", "", obuf);
		col = token_print_indent (file, col, scol, "", " ",
					  ",");
		col = write_expression (file, expr -> data.ns_add.rrname,
					col, scol, 0);
		col = token_print_indent (file, col, scol, "", " ",
					  ",");
		col = write_expression (file, expr -> data.ns_add.rrdata,
					col, scol, 0);
		col = token_print_indent (file, col, scol, "", " ",
					  ",");
		col = write_expression (file, expr -> data.ns_add.ttl,
					col, scol, 0);
		col = token_print_indent (file, col, indent, "", "",
					  ")");
		break;

	      case expr_ns_delete:
		col = token_print_indent (file, col, indent, "", "",
					  "delete");
		col = token_print_indent (file, col, indent, " ", "",
					  "(");
	      finish_ns_small:
		scol = col;
		sprintf (obuf, "%d", expr -> data.ns_add.rrclass);
		col = token_print_indent (file, col, scol, "", "", obuf);
		col = token_print_indent (file, col, scol, "", " ",
					  ",");
		sprintf (obuf, "%d", expr -> data.ns_add.rrtype);
		col = token_print_indent (file, col, scol, "", "", obuf);
		col = token_print_indent (file, col, scol, "", " ",
					  ",");
		col = write_expression (file, expr -> data.ns_add.rrname,
					col, scol, 0);
		col = token_print_indent (file, col, scol, "", " ",
					  ",");
		col = write_expression (file, expr -> data.ns_add.rrdata,
					col, scol, 0);
		col = token_print_indent (file, col, indent, "", "",
					  ")");
		break;

	      case expr_ns_exists:
		col = token_print_indent (file, col, indent, "", "",
					  "exists");
		col = token_print_indent (file, col, indent, " ", "",
					  "(");
		goto finish_ns_small;

	      case expr_ns_not_exists:
		col = token_print_indent (file, col, indent, "", "",
					  "not exists");
		col = token_print_indent (file, col, indent, " ", "",
					  "(");
		goto finish_ns_small;

	      case expr_static:
		col = token_print_indent (file, col, indent, "", "",
					  "static");
		break;

	      case expr_null:
		col = token_print_indent (file, col, indent, "", "", "null");
		break;

	      case expr_variable_reference:
		col = token_print_indent (file, indent, indent, "", "",
					  expr -> data.variable);
		break;

	      case expr_variable_exists:
		col = token_print_indent (file, indent, indent, "", "",
					  "defined");
		col = token_print_indent (file, col, indent, " ", "", "(");
		col = token_print_indent (file, col, indent, "", "",
					  expr -> data.variable);
		col = token_print_indent (file, col, indent, "", "", ")");
		break;

	      default:
		log_fatal ("invalid expression type in print_expression: %d",
			   expr -> op);
	}
	return col;
}
/* vim: set tabstop=8: */
