/* omapictl.c

   Examine and modify omapi objects. */

/*
 * Copyright (c) 2001 Internet Software Consortium.
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
 * by Ted Lemon in cooperation with Vixie Enterprises and Nominum, Inc.
 * To learn more about the Internet Software Consortium, see
 * ``http://www.isc.org/''.  To learn more about Vixie Enterprises,
 * see ``http://www.vix.com''.   To learn more about Nominum, Inc., see
 * ``http://www.nominum.com''.
 */

#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <isc/result.h>
#include "dhcpctl.h"
#include "dhcpd.h"

/* Fixups */
isc_result_t find_class (struct class **c, const char *n, const char *f, int l)
{
	return 0;
}
int parse_allow_deny (struct option_cache **oc, struct parse *cfile, int flag)
{
	return 0;
}
void dhcp (struct packet *packet) { }
void bootp (struct packet *packet) { }
int check_collection (struct packet *p, struct lease *l, struct collection *c)
{
	return 0;
}
void classify (struct packet *packet, struct class *class) { }

static void usage (char *s) {
	fprintf (stderr,
		 "Usage: %s [-n <username>] [-p <password>] "
		 "[-a <algorithm>]\n", s);
	exit (1);
}

int main (int argc, char **argv, char **envp)
{
	isc_result_t status, waitstatus;
	dhcpctl_handle connection;
	dhcpctl_handle authenticator;
	dhcpctl_handle oh;
	dhcpctl_data_string cid, ip_addr;
	dhcpctl_data_string result, groupname, identifier;
	const char *name = 0, *pass = 0, *algorithm = "hmac-md5";
	int i;
	int port = 7911;
	const char *server = "127.0.0.1";
	struct parse *cfile;
	enum dhcp_token token;
	const char *val;

	for (i = 1; i < argc; i++) {
		if (!strcmp (argv[i], "-n")) {
			if (++i == argc)
				usage(argv[0]);
			name = argv[i];
		} else if (!strcmp (argv[i], "-p")) {
			if (++i == argc)
				usage(argv[0]);
			pass = argv[i];
		} else if (!strcmp (argv[i], "-a")) {
			if (++i == argc)
				usage(argv[0]);
			algorithm = argv[i];
		} else if (!strcmp (argv[i], "-s")) {
			if (++i == argc)
				usage(argv[0]);
			server = argv[i];
		} else if (!strcmp (argv[i], "-P")) {
			if (++i == argc)
				usage(argv[0]);
			port = atoi (argv[i]);
		} else {
			usage(argv[0]);
		}
	}

	if ((name || pass) && !(name && pass))
		usage(argv[0]);

	status = dhcpctl_initialize ();
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_initialize: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	authenticator = dhcpctl_null_handle;

	if (name) {
		status = dhcpctl_new_authenticator (&authenticator,
						    name, algorithm, pass,
						    strlen (pass) + 1);
		if (status != ISC_R_SUCCESS) {
			fprintf (stderr, "Cannot create authenticator: %s\n",
				 isc_result_totext (status));
			exit (1);
		}
	}

	memset (&connection, 0, sizeof connection);
	status = dhcpctl_connect (&connection, server, port, authenticator);
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_connect: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	memset (&oh, 0, sizeof oh);

	cfile = (struct parse *)0;
	new_parse (&cfile, 0, (char *)0, 0, "<STDIN>");
	do {
		token = next_token (&val, cfile);
		switch (token) {
		      default:
			parse_warn (cfile, "unknown token: %s", val);
			skip_to_semi (cfile);
			break;

		      case TOKEN_NEW:
			if (oh) {
				parse_warn (cfile,
					    "an object is already open.");
				skip_to_semi (cfile);
				break;
			}
			token = next_token (&val, cfile);
			if (!is_identifier (token) && token != STRING) {
				parse_warn (cfile,
					    "expecting an object name.");
				skip_to_semi (cfile);
				break;
			}
			status = dhcpctl_new_object (&oh, connection, val);
			if (status != ISC_R_SUCCESS) {
				fprintf (stderr, "dhcpctl_new_object: %s\n",
					 isc_result_totext (status));
				exit (1);
			}
			parse_semi (cfile);
			break;

		}
	} while (1);

#if 0
	memset (&cid, 0, sizeof cid);
	status = omapi_data_string_new (&cid, 6, MDL);
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "omapi_data_string_new: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	memset (&cid -> value [0], 0, 6);

	status = dhcpctl_set_value (host_handle,
				    cid, "hardware-address");
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_set_value: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	status = dhcpctl_set_string_value (host_handle, "gnorf",
					   "name");
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_set_string_value: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

#if 0
	memset (&ip_addr, 0, sizeof ip_addr);
	status = omapi_data_string_new (&ip_addr, 4, MDL);
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "omapi_data_string_new: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	ip_addr -> value [0] = 10; ip_addr -> value [1] = 0;
	ip_addr -> value [2] = 0; ip_addr -> value [3] = 2;

	status = dhcpctl_set_value (host_handle, ip_addr, "ip-address");
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_set_value: %s\n",
			 isc_result_totext (status));
		exit (1);
	}
#endif

	/* Set the known flag to 1. */
	status = dhcpctl_set_boolean_value (host_handle, 1, "known");
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_set_boolean_value: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

#if 0
       status = dhcpctl_set_string_value (host_handle, "\n\
option host-name \"bar\";\n\
option smtp-server 10.0.0.1;",
                                          "statements");
       if (status != ISC_R_SUCCESS) {
               fprintf (stderr, "dhcpctl_set_value: %s\n",
                        isc_result_totext (status));
               exit (1);
       }
#endif

	status = dhcpctl_open_object (host_handle, connection,
				      DHCPCTL_CREATE | DHCPCTL_EXCL);
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_open_object: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	status = dhcpctl_wait_for_completion (host_handle, &waitstatus);
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "create: dhcpctl_wait_for_completion: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	if (waitstatus != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_open_object: %s\n",
			 isc_result_totext (waitstatus));
		exit (1);
	}

	cid -> value [0] = 0; cid -> value [1] = 0x10;
	cid -> value [2] = 0x5a; cid -> value [3] = 0xf8;
	cid -> value [4] = 0x00; cid -> value [5] = 0xbb;

	status = dhcpctl_set_value (host_handle,
				    cid, "hardware-address");
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_set_value: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	status = dhcpctl_object_update (connection, host_handle);
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_object_update: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	status = dhcpctl_wait_for_completion (host_handle, &waitstatus);
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "update: dhcpctl_wait_for_completion: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	if (waitstatus != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_object_update: %s\n",
			 isc_result_totext (waitstatus));
		exit (1);
	}

	status = dhcpctl_object_remove (connection, host_handle);
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_object_remove: %s\n",
			 isc_result_totext (status));
		exit (1);
	}
	status = dhcpctl_wait_for_completion (host_handle,
					      &waitstatus);
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr,
			 "remove: dhcpctl_wait_for_completion: %s\n",
			 isc_result_totext (status));
		exit (1);
	}
	if (waitstatus != ISC_R_SUCCESS) {
		fprintf (stderr,
			 "remove: dhcpctl_wait_for_completion: %s\n",
			 isc_result_totext (waitstatus));
		exit (1);
	}

	omapi_object_dereference (&host_handle, MDL);

	status = dhcpctl_new_object (&host_handle, connection, "host");
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_new_object: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	memset (&cid -> value [0], 0, 6);

	status = dhcpctl_set_value (host_handle,
				    cid, "hardware-address");
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_set_value: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	status = dhcpctl_set_string_value (host_handle, "gnorf",
					   "name");
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_set_string_value: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	status = dhcpctl_open_object (host_handle, connection,
				      DHCPCTL_CREATE | DHCPCTL_EXCL);
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_open_object 2: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	status = dhcpctl_wait_for_completion (host_handle, &waitstatus);
	if (status != ISC_R_SUCCESS) {
		fprintf (stderr, "create: dhcpctl_wait_for_completion: %s\n",
			 isc_result_totext (status));
		exit (1);
	}

	if (waitstatus != ISC_R_SUCCESS) {
		fprintf (stderr, "dhcpctl_open_object 2: %s\n",
			 isc_result_totext (waitstatus));
		exit (1);
	}
#endif
	exit (0);
}
