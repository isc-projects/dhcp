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
	const unsigned char *data;
	unsigned len;	/* Does not include NUL terminator, if any. */
	int terminated;
};

enum expression_context {
	context_any, /* indefinite */
	context_boolean,
	context_data,
	context_numeric,
	context_dns,
	context_data_or_numeric, /* indefinite */
	context_function
};

struct fundef {
	struct string_list *args;
	struct executable_statement *statements;
};

struct binding_value {
	int refcnt;
	enum {
		binding_boolean,
		binding_data,
		binding_numeric,
		binding_dns,
		binding_function
	} type;
	union value {
		struct data_string data;
		unsigned long intval;
		int boolean;
		ns_updrec *dns;
		struct fundef fundef;
	} value;
};

struct binding {
	struct binding *next;
	char *name;
	struct binding_value *value;
};

struct binding_scope {
	struct binding_scope *outer;
	struct binding *bindings;
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
	expr_config_option,
	expr_host_decl_name,
	expr_pick_first_value,
 	expr_lease_time,
 	expr_dns_transaction,
	expr_static,
	expr_ns_add,
 	expr_ns_delete,
 	expr_ns_exists,
 	expr_ns_not_exists,
	expr_not_equal,
	expr_null,
	expr_variable_exists,
	expr_variable_reference,
	expr_filename,
 	expr_sname,
	expr_arg,
	expr_funcall
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
		struct option *config_option;
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
		struct {
			struct expression *car;
			struct expression *cdr;
		} pick_first_value;
		struct {
			struct expression *car;
			struct expression *cdr;
		} dns_transaction;
 		struct {
			unsigned rrclass;
			unsigned rrtype;
 			struct expression *rrname;
 			struct expression *rrdata;
 			struct expression *ttl;
 		} ns_add;
 		struct {
			unsigned rrclass;
			unsigned rrtype;
 			struct expression *rrname;
 			struct expression *rrdata;
 		} ns_delete, ns_exists, ns_not_exists;
		char *variable;
		struct {
			struct expression *val;
			struct expression *next;
		} arg;
		struct {
			char *name;
			struct expression *arglist;
		} funcall;
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
struct packet; /* forward */
struct option_state; /* forward */
struct decoded_option_state; /* forward */
struct lease; /* forward */

struct universe {
	const char *name;
	struct option_cache *(*lookup_func) PROTO ((struct universe *,
						    struct option_state *,
						    unsigned));
	void (*save_func) PROTO ((struct universe *, struct option_state *,
				  struct option_cache *));
	int (*get_func) PROTO ((struct data_string *, struct universe *,
				struct packet *, struct lease *,
				struct option_state *, struct option_state *,
				struct option_state *, struct binding_scope *,
				unsigned));
	void (*set_func) PROTO ((struct universe *, struct option_state *,
				 struct option_cache *, enum statement_op));
		
	void (*delete_func) PROTO ((struct universe *universe,
				    struct option_state *, int));
	int (*option_state_dereference) PROTO ((struct universe *,
						struct option_state *,
						const char *, int));
	int (*encapsulate) PROTO ((struct data_string *, struct packet *,
				   struct lease *, struct option_state *,
				   struct option_state *,
				   struct binding_scope *, struct universe *));
	void (*store_tag) PROTO ((unsigned char *, u_int32_t));
	void (*store_length) PROTO ((unsigned char *, u_int32_t));
	int tag_size, length_size;
	struct hash_table *hash;
	struct option *options [256];
	int index;
};

struct option {
	const char *name;
	const char *format;
	struct universe *universe;
	unsigned code;
};
