/* tree.h

   Definitions for address trees... */

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

/* A data buffer with a reference count. */
struct buffer {
	int refcnt;
	unsigned char data [1];
};

/* XXX The mechanism by which data strings are returned is currently
   XXX broken: rather than returning an ephemeral pointer, we create
   XXX a reference to the data in the caller's space, which the caller
   XXX then has to dereference - instead, the reference should be
   XXX ephemeral by default and be made a persistent reference explicitly. */
/* XXX on the other hand, it seems to work pretty nicely, so maybe the
   XXX above comment is meshuggenah. */

/* A string of data bytes, possibly accompanied by a larger buffer. */
struct data_string {
	struct buffer *buffer;
	unsigned char *data;
	int len;
	int terminated;
};

/* Expression tree structure. */

enum expr_op {
	expr_none,
	expr_match,
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
	expr_encode_int8,
	expr_encode_int16,
	expr_encode_int32,
	expr_const_int,
	expr_exists,
	expr_encapsulate,
	expr_known,
	expr_reverse,
	expr_leased_address,
	expr_binary_to_ascii,
};

struct expression {
	int refcnt;
	enum expr_op op;
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
		struct expression *extract_int;
		struct expression *encode_int;
		unsigned long const_int;
		struct expression *concat [2];
		struct dns_host_entry *host_lookup;
		struct option *exists;
		struct data_string encapsulate;
		struct {
			struct expression *base;
			struct expression *width;
			struct expression *seperator;
			struct expression *buffer;
		} b2a;
		struct {
			struct expression *width;
			struct expression *buffer;
		} reverse;
	} data;
	int flags;
#	define EXPR_EPHEMERAL	1
};		

/* DNS host entry structure... */
struct dns_host_entry {
	int refcnt;
	TIME timeout;
	struct data_string data;
	char hostname [1];
};

struct option_cache; /* forward */
struct data_string; /* forward */
struct packet; /* forward */
struct option_state; /* forward */
struct decoded_option_state; /* forward */
struct lease; /* forward */

struct universe {
	char *name;
	struct option_cache *(*lookup_func) PROTO ((struct universe *,
						    struct option_state *,
						    int));
	void (*save_func) PROTO ((struct universe *, struct option_state *,
				  struct option_cache *));
	int (*get_func) PROTO ((struct data_string *, struct universe *,
				struct packet *, struct lease *,
				struct option_state *, int));
	void (*set_func) PROTO ((struct universe *, struct option_state *,
				 struct option_cache *, enum statement_op));
		
	void (*delete_func) PROTO ((struct universe *universe,
				    struct option_state *, int));
	int (*option_state_dereference) PROTO ((struct universe *,
						struct option_state *));
	int (*encapsulate) PROTO ((struct data_string *, struct option_state *,
				   struct lease *, struct universe *));
	void (*store_tag) PROTO ((unsigned char *, u_int32_t));
	void (*store_length) PROTO ((unsigned char *, u_int32_t));
	int tag_size, length_size;
	struct hash_table *hash;
	struct option *options [256];
	int index;
};

struct option {
	char *name;
	char *format;
	struct universe *universe;
	int code;
};

enum expression_context {
	context_any,
	context_boolean,
	context_data,
	context_numeric
};
