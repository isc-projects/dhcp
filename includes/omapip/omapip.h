/* omapip.h

   Definitions for the object management API and protocol... */

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

#ifndef __CYGWIN32__
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

#if defined (NSUPDATE)
# include <arpa/nameser.h>
# include <resolv.h>
#endif

#include <netdb.h>
#else
#define fd_set cygwin_fd_set
#include <sys/types.h>
#endif
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <ctype.h>
#include <time.h>

#include "cdefs.h"
#include "osdep.h"

#include <isc/result.h>

typedef u_int32_t omapi_handle_t;

/* OMAPI protocol header, version 1.00 */
typedef struct {
	int authlen;	/* Length of authenticator. */
	int authid;	/* Authenticator object ID. */
	int op;		/* Opcode. */
	omapi_handle_t handle;	/* Handle of object being operated on,
                                   or zero. */
	int id;		/* Transaction ID. */
	int rid;	/* ID of transaction to which this is a response. */
} omapi_protocol_header_t;

struct __omapi_object;
typedef struct __omapi_object omapi_object_t;

typedef enum {
	omapi_datatype_int,
	omapi_datatype_string,
	omapi_datatype_data,
	omapi_datatype_object,
} omapi_datatype_t;

typedef struct {
	int refcnt;
	omapi_datatype_t type;
	union {
		struct {
			int len;
#define OMAPI_TYPED_DATA_NOBUFFER_LEN (sizeof (int) + \
				       sizeof (omapi_datatype_t) + \
				       sizeof (int))
			u_int8_t value [1];
		} buffer;
#define OMAPI_TYPED_DATA_OBJECT_LEN (sizeof (int) + \
				     sizeof (omapi_datatype_t) + \
				     sizeof (omapi_object_t *))
		omapi_object_t *object;
#define OMAPI_TYPED_DATA_REF_LEN (sizeof (int) + \
				  sizeof (omapi_datatype_t) + \
				  3 * sizeof (void *))
		struct {
			void *ptr;
			isc_result_t (*reference) (void *,
						   void *, char *);
			isc_result_t (*dereference) (void *, char *);
		} ref;
#define OMAPI_TYPED_DATA_INT_LEN (sizeof (int) + \
				  sizeof (omapi_datatype_t) + \
				  sizeof (int))
		int integer;
	} u;
} omapi_typed_data_t;

typedef struct {
	int refcnt;
	int len;
#define OMAPI_DATA_STRING_EMPTY_SIZE (2 * sizeof (int))
	u_int8_t value [1];
} omapi_data_string_t;

typedef struct {
	int refcnt;
	omapi_data_string_t *name;
	omapi_typed_data_t *value;
} omapi_value_t;

typedef struct __omapi_object_type_t {
	char *name;
	struct __omapi_object_type_t *next;
	
	isc_result_t (*set_value) (omapi_object_t *, omapi_object_t *,
				   omapi_data_string_t *,
				   omapi_typed_data_t *);
	isc_result_t (*get_value) (omapi_object_t *,
				   omapi_object_t *,
				   omapi_data_string_t *, omapi_value_t **);
	isc_result_t (*destroy) (omapi_object_t *, char *);
	isc_result_t (*signal_handler) (omapi_object_t *, char *, va_list);
	isc_result_t (*stuff_values) (omapi_object_t *,
				      omapi_object_t *, omapi_object_t *);
	isc_result_t (*lookup) (omapi_object_t **, omapi_object_t *,
				omapi_object_t *);
	isc_result_t (*create) (omapi_object_t **, omapi_object_t *);
} omapi_object_type_t;

#define OMAPI_OBJECT_PREAMBLE \
	omapi_object_type_t *type; \
	int refcnt; \
	omapi_handle_t handle; \
	omapi_object_t *outer, *inner

/* The omapi handle structure. */
struct __omapi_object {
	OMAPI_OBJECT_PREAMBLE;
};

#define OMAPI_PROTOCOL_PORT	7911
#define OMAPI_PROTOCOL_VERSION	100

#define OMAPI_OP_OPEN		1
#define OMAPI_OP_REFRESH	2
#define	OMAPI_OP_UPDATE		3
#define OMAPI_OP_NOTIFY		4
#define OMAPI_OP_STATUS		5

#include <omapip/buffer.h>

typedef enum {
	omapi_connection_unconnected,
	omapi_connection_connecting,
	omapi_connection_connected,
	omapi_connection_disconnecting,
	omapi_connection_closed,
} omapi_connection_state_t;

typedef enum {
	omapi_protocol_intro_wait,
	omapi_protocol_header_wait,
	omapi_protocol_signature_wait,
	omapi_protocol_name_wait,
	omapi_protocol_name_length_wait,
	omapi_protocol_value_wait,
	omapi_protocol_value_length_wait,
} omapi_protocol_state_t;

typedef struct __omapi_message_object {
	OMAPI_OBJECT_PREAMBLE;
	struct __omapi_message_object *next, *prev;
	omapi_object_t *object;
	int authlen;
	omapi_typed_data_t *authenticator;
	int authid;
	omapi_object_t *id_object;
	int op;
	omapi_handle_t h;
	int id;
	int rid;
} omapi_message_object_t;

typedef struct {
	OMAPI_OBJECT_PREAMBLE;
	int header_size;		
	int protocol_version;
	u_int32_t next_xid;
	omapi_object_t *authinfo; /* Default authinfo to use. */

	omapi_protocol_state_t state;	/* Input state. */
	int reading_message_values;	/* True if reading message-specific
					   values. */
	omapi_message_object_t *message;	/* Incoming message. */
	omapi_data_string_t *name;	/* Incoming name. */
	omapi_typed_data_t *value;	/* Incoming value. */
} omapi_protocol_object_t;

typedef struct {
	OMAPI_OBJECT_PREAMBLE;
} omapi_protocol_listener_object_t;

typedef struct __omapi_connection_object {
	OMAPI_OBJECT_PREAMBLE;
	int socket;		/* Connection socket. */
	omapi_connection_state_t state;
	struct sockaddr_in remote_addr;
	struct sockaddr_in local_addr;
	u_int32_t bytes_needed;	/* Bytes of input needed before wakeup. */
	u_int32_t in_bytes;	/* Bytes of input already buffered. */
	omapi_buffer_t *inbufs;
	u_int32_t out_bytes;	/* Bytes of output in buffers. */
	omapi_buffer_t *outbufs;
	omapi_object_t *listener;	/* Listener that accepted this
					   connection, if any. */
} omapi_connection_object_t;

typedef struct __omapi_listener_object {
	OMAPI_OBJECT_PREAMBLE;
	int socket;		/* Connection socket. */
	struct sockaddr_in address;
} omapi_listener_object_t;

typedef struct __omapi_io_object {
	OMAPI_OBJECT_PREAMBLE;
	struct __omapi_io_object *next;
	int (*readfd) (omapi_object_t *);
	int (*writefd) (omapi_object_t *);
	isc_result_t (*reader) (omapi_object_t *);
	isc_result_t (*writer) (omapi_object_t *);
	isc_result_t (*reaper) (omapi_object_t *);
} omapi_io_object_t;

typedef struct __omapi_generic_object {
	OMAPI_OBJECT_PREAMBLE;
	omapi_value_t **values;
	int nvalues, va_max;
} omapi_generic_object_t;

typedef struct __omapi_waiter_object {
	OMAPI_OBJECT_PREAMBLE;
	int ready;
	struct __omapi_waiter_object *next;
} omapi_waiter_object_t;

#define OMAPI_HANDLE_TABLE_SIZE 120

typedef struct __omapi_handle_table {
	omapi_handle_t first, limit;
	omapi_handle_t next;
	int leafp;
	union {
		omapi_object_t *object;
		struct __omapi_handle_table *table;
	} children [OMAPI_HANDLE_TABLE_SIZE];
} omapi_handle_table_t;

#include <omapip/alloc.h>

isc_result_t omapi_protocol_connect (omapi_object_t *,
				     char *, int, omapi_object_t *);
isc_result_t omapi_protocol_listen (omapi_object_t *, int, int);
isc_result_t omapi_protocol_accept (omapi_object_t *);
isc_result_t omapi_protocol_send_intro (omapi_object_t *, int, int);
isc_result_t omapi_protocol_ready (omapi_object_t *);
isc_result_t omapi_protocol_set_value (omapi_object_t *, omapi_object_t *,
				       omapi_data_string_t *,
				       omapi_typed_data_t *);
isc_result_t omapi_protocol_get_value (omapi_object_t *, omapi_object_t *,
				       omapi_data_string_t *,
				       omapi_value_t **); 
isc_result_t omapi_protocol_stuff_values (omapi_object_t *,
					  omapi_object_t *,
					  omapi_object_t *);

isc_result_t omapi_protocol_destroy (omapi_object_t *, char *);
isc_result_t omapi_protocol_send_message (omapi_object_t *,
					  omapi_object_t *,
					  omapi_object_t *,
					  omapi_object_t *);
isc_result_t omapi_protocol_signal_handler (omapi_object_t *, char *, va_list);
isc_result_t omapi_protocol_listener_set_value (omapi_object_t *,
						omapi_object_t *,
						omapi_data_string_t *,
						omapi_typed_data_t *);
isc_result_t omapi_protocol_listener_get_value (omapi_object_t *,
						omapi_object_t *,
						omapi_data_string_t *,
						omapi_value_t **); 
isc_result_t omapi_protocol_listener_destroy (omapi_object_t *, char *);
isc_result_t omapi_protocol_listener_signal (omapi_object_t *,
					     char *, va_list);
isc_result_t omapi_protocol_listener_stuff (omapi_object_t *,
					    omapi_object_t *,
					    omapi_object_t *);
isc_result_t omapi_protocol_send_status (omapi_object_t *, omapi_object_t *,
					 isc_result_t, int, char *);
isc_result_t omapi_protocol_send_update (omapi_object_t *, omapi_object_t *,
					 int, omapi_object_t *);

isc_result_t omapi_connect (omapi_object_t *, char *, int);
isc_result_t omapi_disconnect (omapi_object_t *, int);
int omapi_connection_readfd (omapi_object_t *);
int omapi_connection_writefd (omapi_object_t *);
isc_result_t omapi_connection_reader (omapi_object_t *);
isc_result_t omapi_connection_writer (omapi_object_t *);
isc_result_t omapi_connection_reaper (omapi_object_t *);
isc_result_t omapi_connection_set_value (omapi_object_t *, omapi_object_t *,
					 omapi_data_string_t *,
					 omapi_typed_data_t *);
isc_result_t omapi_connection_get_value (omapi_object_t *, omapi_object_t *,
					 omapi_data_string_t *,
					 omapi_value_t **); 
isc_result_t omapi_connection_destroy (omapi_object_t *, char *);
isc_result_t omapi_connection_signal_handler (omapi_object_t *,
					      char *, va_list);
isc_result_t omapi_connection_stuff_values (omapi_object_t *,
					    omapi_object_t *,
					    omapi_object_t *);
isc_result_t omapi_connection_write_typed_data (omapi_object_t *,
						omapi_typed_data_t *);
isc_result_t omapi_connection_put_name (omapi_object_t *, char *);
isc_result_t omapi_connection_put_string (omapi_object_t *, char *);
isc_result_t omapi_connection_put_handle (omapi_object_t *c,
					  omapi_object_t *h);


isc_result_t omapi_listen (omapi_object_t *, int, int);
isc_result_t omapi_listener_accept (omapi_object_t *);
int omapi_listener_readfd (omapi_object_t *);
isc_result_t omapi_accept (omapi_object_t *);
isc_result_t omapi_listener_set_value (omapi_object_t *, omapi_object_t *,
				       omapi_data_string_t *,
				       omapi_typed_data_t *);
isc_result_t omapi_listener_get_value (omapi_object_t *, omapi_object_t *,
				       omapi_data_string_t *,
				       omapi_value_t **); 
isc_result_t omapi_listener_destroy (omapi_object_t *, char *);
isc_result_t omapi_listener_signal_handler (omapi_object_t *, char *, va_list);
isc_result_t omapi_listener_stuff_values (omapi_object_t *,
					  omapi_object_t *,
					  omapi_object_t *);

isc_result_t omapi_register_io_object (omapi_object_t *,
				       int (*)(omapi_object_t *),
				       int (*)(omapi_object_t *),
				       isc_result_t (*)(omapi_object_t *),
				       isc_result_t (*)(omapi_object_t *),
				       isc_result_t (*)(omapi_object_t *));
isc_result_t omapi_dispatch (struct timeval *);
isc_result_t omapi_wait_for_completion (omapi_object_t *, struct timeval *);
isc_result_t omapi_one_dispatch (omapi_waiter_object_t *, struct timeval *);
isc_result_t omapi_io_set_value (omapi_object_t *, omapi_object_t *,
				 omapi_data_string_t *,
				 omapi_typed_data_t *);
isc_result_t omapi_io_get_value (omapi_object_t *, omapi_object_t *,
				 omapi_data_string_t *, omapi_value_t **); 
isc_result_t omapi_io_destroy (omapi_object_t *, char *);
isc_result_t omapi_io_signal_handler (omapi_object_t *, char *, va_list);
isc_result_t omapi_io_stuff_values (omapi_object_t *,
				    omapi_object_t *,
				    omapi_object_t *);
isc_result_t omapi_waiter_signal_handler (omapi_object_t *, char *, va_list);

isc_result_t omapi_generic_new (omapi_object_t **, char *);
isc_result_t omapi_generic_set_value  (omapi_object_t *, omapi_object_t *,
				       omapi_data_string_t *,
				       omapi_typed_data_t *);
isc_result_t omapi_generic_get_value (omapi_object_t *, omapi_object_t *,
				      omapi_data_string_t *,
				      omapi_value_t **); 
isc_result_t omapi_generic_destroy (omapi_object_t *, char *);
isc_result_t omapi_generic_signal_handler (omapi_object_t *, char *, va_list);
isc_result_t omapi_generic_stuff_values (omapi_object_t *,
					 omapi_object_t *,
					 omapi_object_t *);

isc_result_t omapi_message_new (omapi_object_t **, char *);
isc_result_t omapi_message_set_value  (omapi_object_t *, omapi_object_t *,
				       omapi_data_string_t *,
				       omapi_typed_data_t *);
isc_result_t omapi_message_get_value (omapi_object_t *, omapi_object_t *,
				      omapi_data_string_t *,
				      omapi_value_t **); 
isc_result_t omapi_message_destroy (omapi_object_t *, char *);
isc_result_t omapi_message_signal_handler (omapi_object_t *, char *, va_list);
isc_result_t omapi_message_stuff_values (omapi_object_t *,
					 omapi_object_t *,
					 omapi_object_t *);
isc_result_t omapi_message_register (omapi_object_t *);
isc_result_t omapi_message_unregister (omapi_object_t *);
isc_result_t omapi_message_process (omapi_object_t *, omapi_object_t *);

extern omapi_object_type_t *omapi_type_connection;
extern omapi_object_type_t *omapi_type_listener;
extern omapi_object_type_t *omapi_type_io_object;
extern omapi_object_type_t *omapi_type_generic;
extern omapi_object_type_t *omapi_type_protocol;
extern omapi_object_type_t *omapi_type_protocol_listener;
extern omapi_object_type_t *omapi_type_waiter;
extern omapi_object_type_t *omapi_type_remote;
extern omapi_object_type_t *omapi_type_message;

extern omapi_object_type_t *omapi_object_types;

isc_result_t omapi_init (void);
isc_result_t omapi_object_type_register (omapi_object_type_t **,
					 char *,
					 isc_result_t (*)
						(omapi_object_t *,
						 omapi_object_t *,
						 omapi_data_string_t *,
						 omapi_typed_data_t *),
					 isc_result_t (*)
						(omapi_object_t *,
						 omapi_object_t *,
						 omapi_data_string_t *,
						 omapi_value_t **),
					 isc_result_t (*) (omapi_object_t *,
							   char *),
					 isc_result_t (*) (omapi_object_t *,
							   char *, va_list),
					 isc_result_t (*) (omapi_object_t *,
							   omapi_object_t *,
							   omapi_object_t *),
					 isc_result_t (*) (omapi_object_t **,
							   omapi_object_t *,
							   omapi_object_t *),
					 isc_result_t (*) (omapi_object_t **,
							   omapi_object_t *));
isc_result_t omapi_signal (omapi_object_t *, char *, ...);
isc_result_t omapi_signal_in (omapi_object_t *, char *, ...);
isc_result_t omapi_set_value (omapi_object_t *, omapi_object_t *,
			      omapi_data_string_t *,
			      omapi_typed_data_t *);
isc_result_t omapi_set_value_str (omapi_object_t *, omapi_object_t *,
				  char *, omapi_typed_data_t *);
isc_result_t omapi_set_boolean_value (omapi_object_t *, omapi_object_t *,
				      char *, int);
isc_result_t omapi_set_int_value (omapi_object_t *, omapi_object_t *,
				  char *, int);
isc_result_t omapi_set_object_value (omapi_object_t *, omapi_object_t *,
				     char *, omapi_object_t *);
isc_result_t omapi_set_string_value (omapi_object_t *, omapi_object_t *,
				     char *, char *);
isc_result_t omapi_get_value (omapi_object_t *, omapi_object_t *,
			      omapi_data_string_t *,
			      omapi_value_t **); 
isc_result_t omapi_get_value_str (omapi_object_t *, omapi_object_t *,
				  char *, omapi_value_t **); 
isc_result_t omapi_stuff_values (omapi_object_t *,
				 omapi_object_t *,
				 omapi_object_t *);
isc_result_t omapi_object_create (omapi_object_t **, omapi_object_t *,
				  omapi_object_type_t *);
isc_result_t omapi_object_update (omapi_object_t *, omapi_object_t *,
				  omapi_object_t *);
int omapi_data_string_cmp (omapi_data_string_t *, omapi_data_string_t *);
int omapi_ds_strcmp (omapi_data_string_t *, char *);
int omapi_td_strcmp (omapi_typed_data_t *, char *);
isc_result_t omapi_make_value (omapi_value_t **, omapi_data_string_t *,
			       omapi_typed_data_t *, char *);
isc_result_t omapi_make_const_value (omapi_value_t **, omapi_data_string_t *,
				     u_int8_t *, int, char *);
isc_result_t omapi_make_int_value (omapi_value_t **, omapi_data_string_t *,
				   int, char *);
isc_result_t omapi_make_handle_value (omapi_value_t **, omapi_data_string_t *,
				      omapi_object_t *, char *);
isc_result_t omapi_make_string_value (omapi_value_t **, omapi_data_string_t *,
				      char *, char *);
isc_result_t omapi_get_int_value (u_int32_t *, omapi_typed_data_t *);



isc_result_t omapi_object_handle (omapi_handle_t *, omapi_object_t *);
isc_result_t omapi_handle_lookup (omapi_object_t **, omapi_handle_t);
isc_result_t omapi_handle_td_lookup (omapi_object_t **, omapi_typed_data_t *);
