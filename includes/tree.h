/* tree.h

   Definitions for address trees... */

/*
 * Copyright (c) 1995, 1998 The Internet Software Consortium.
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

/* A pair of pointers, suitable for making a linked list. */
typedef struct _pair {
	caddr_t car;
	struct _pair *cdr;
} *pair;

/* Tree node types... */
#define TREE_CONCAT		1
#define TREE_HOST_LOOKUP	2
#define TREE_CONST		3
#define TREE_LIMIT		4
#define TREE_DATA_EXPR		5

/* A string of data bytes, possibly accompanied by a larger buffer. */
struct data_string {
	unsigned char *data, *buffer;
	int len;
	int terminated;
};

/* Expression tree structure. */

struct expression {
	enum {
		expr_check,
		expr_equal,
		expr_substring,
		expr_suffix,
		expr_concat,
		expr_host_lookup,
		expr_and,
		expr_or,
		expr_not,
		expr_option,
		expr_hardware,
		expr_packet,
		expr_const_data,
		expr_extract_int8,
		expr_extract_int16,
		expr_extract_int32,
		expr_const_int,
	} op;
	union {
		struct {
			struct expression *expr;
			struct expression *offset;
			struct expression *len;
		} substring;
		struct expression *equal [2];
		struct expression *and [2];
		struct expression *or [2];
		struct expression *not;
		struct collection *check;
		struct {
			struct expression *expr;
			struct expression *len;
		} suffix;
		struct option *option;
		struct {
			struct expression *offset;
			struct expression *len;
		} packet;
		struct data_string const_data;
		struct {
			struct expression *expr;
			struct expression *width;
		} extract_int;
		unsigned long const_int;
		struct expression *concat [2];
		struct dns_host_entry *host_lookup;
	} data;
	int flags;
#	define EXPR_EPHEMERAL	1
};		

/* DNS host entry structure... */
struct dns_host_entry {
	char *hostname;
	char *buffer;
	int buf_len;
	int data_len;
	TIME timeout;
};

struct option_cache {
	struct expression *expression;
	struct option *option;
};

struct data_string; /* forward */
struct packet; /* forward */
struct option_state; /* forward */
enum statement_op; /* forward */

struct universe {
	char *name;
	struct data_string (*lookup_func) PROTO ((struct packet *, int));
	void (*set_func) PROTO ((struct option_state *,
				 struct option_cache *,
				 enum statement_op));
	struct hash_table *hash;
	struct option *options [256];
};

struct option {
	char *name;
	char *format;
	struct universe *universe;
	unsigned char code;
};
