/* statement.h

   Definitions for executable statements... */

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

struct executable_statement {
	struct executable_statement *next;
	enum statement_op {
		if_statement,
		add_statement,
		eval_statement,
		break_statement,
		default_option_statement,
		supersede_option_statement,
		append_option_statement,
		prepend_option_statement,
		send_option_statement,
	} op;
	union {
		struct {
			struct executable_statement *true, *false;
			struct expression *expr;
		} ie;
		struct expression *eval;
		struct class *add;
		struct option_cache *option;
		struct option_cache *supersede;
		struct option_cache *prepend;
		struct option_cache *append;
	} data;
};

