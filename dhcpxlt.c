/* confpars.c

   Translate old (Beta 4 and previous) dhcpd config files... */

/*
 * Copyright (c) 1995, 1996 The Internet Software Consortium.
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
"$Id: dhcpxlt.c,v 1.1 1996/08/27 09:40:53 mellon Exp $ Copyright (c) 1996 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"
#include "dhctoken.h"

static TIME parsed_time;
int log_priority;

int main (argc, argv, envp)
	int argc;
	char **argv;
	char **envp;
{
	initialize_universes ();
	readconf ();
	exit (0);
}

void cleanup () {
}

/* conf-file :== statements
   declarations :== <nil> | declaration | declarations declaration */

void readconf ()
{
	FILE *cfile;
	char *val;
	int token;

	new_parse ("stdin");

	cfile = stdin;
	do {
		token = peek_token (&val, cfile);
		if (token == EOF)
			break;
		convert_statement (cfile);
	} while (1);
	token = next_token (&val, cfile);
}

/* statement :== host_statement */

void convert_statement (cfile)
	FILE *cfile;
{
	int token;
	char *val;
	jmp_buf bc;
	int i;

	switch (next_token (&val, cfile)) {
	      case HOST:
		if (!setjmp (bc)) {
			convert_host_statement (cfile, jref (bc));
		}
		break;
	      case LEASE:
		if (!setjmp (bc)) {
			convert_lease_statement (cfile, jref (bc));
		}
		break;
	      case TIMESTAMP:
		if (!setjmp (bc)) {
			convert_timestamp (cfile, jref (bc));
		}
		break;
	      case SHARED_NETWORK:
		if (!setjmp (bc)) {
			convert_shared_net_statement (cfile, jref (bc));
		}
		break;
	      case SUBNET:
		if (!setjmp (bc)) {
			convert_subnet_statement (cfile, jref (bc));
			goto need_semi;
		}
		break;
	      case VENDOR_CLASS:
		if (!setjmp (bc)) {
			convert_class_statement (cfile, jref (bc), 0);
		}
		break;
	      case USER_CLASS:
		if (!setjmp (bc)) {
			convert_class_statement (cfile, jref (bc), 1);
		}
		break;

	      case DEFAULT_LEASE_TIME:
		if (!setjmp (bc)) {
			convert_lease_time (cfile, jref (bc),
					    "default-lease-time");
			goto need_semi;
		}
		break;

	      case MAX_LEASE_TIME:
		if (!setjmp (bc)) {
			convert_lease_time (cfile, jref (bc),
					    "max-lease-time");
			goto need_semi;
		}
		break;

	      case DYNAMIC_BOOTP_LEASE_CUTOFF:
		if (!setjmp (bc)) {
			convert_date (cfile, jref (bc),
				      "dynamic-bootp-lease-cutoff");
			goto need_semi;
		}
		break;

	      case DYNAMIC_BOOTP_LEASE_LENGTH:
		if (!setjmp (bc)) {
			convert_lease_time (cfile, jref (bc),
					    "dynamic-bootp-lease-length ");
			goto need_semi;
		}
		break;

	      case BOOT_UNKNOWN_CLIENTS:
		token = next_token (&val, cfile);
		if (token != NUMBER ||
		    (strcmp (val, "0") && strcmp (val, "1"))) {
			parse_warn ("0 or 1 expected");
			skip_to_semi (cfile);
			break;
		}
		indent (0);
		printf ("boot-unknown-clients %s;\n", val);
		goto need_semi;

	      case NEXT_SERVER:
		if (!setjmp (bc)) {
			indent (0);
			printf ("next-server ");
			convert_ip_addr_or_hostname (cfile, jref (bc), 0);
			printf (";\n");
			goto need_semi;
		}
		break;
			
	      case OPTION:
		if (!setjmp (bc)) {
			convert_option_decl (cfile, jref (bc));
			goto need_semi;
		}
		break;

	      case SERVER_IDENTIFIER:
		if (!setjmp (bc)) {
			indent (0);
			printf ("server-identifier ");
			convert_ip_addr_or_hostname (cfile, jref (bc), 0);
			printf (";\n");
			goto need_semi;
		}
		break;
			
	      default:
		parse_warn ("expecting a declaration.");
		skip_to_semi (cfile);
		break;
	}
	return;

      need_semi:
	token = next_token (&val, cfile);
	if (token != SEMI) {
		parse_warn ("semicolon expected");
		skip_to_semi (cfile);
	}
}

void skip_to_semi (cfile)
	FILE *cfile;
{
	int token;
	char *val;

	do {
		token = next_token (&val, cfile);
	} while (token != SEMI && token != EOF);
}

/* host_statement :== HOST hostname declarations SEMI
   host_declarations :== <nil> | host_declaration
			       | host_declarations host_declaration SEMI */

void convert_host_statement (cfile, bc)
	FILE *cfile;
	jbp_decl (bc);
{
	char *val;
	int token;

	indent (0);
	printf ("host ");
	convert_host_name (cfile, bc);
	printf (" {\n");
	indent (2);
	do {
		token = peek_token (&val, cfile);
		if (token == SEMI) {
			token = next_token (&val, cfile);
			break;
		}
		convert_host_decl (cfile, bc);
	} while (1);

	indent (-2);
	indent (0);
	printf ("}\n");
}

/* host_name :== identifier | host_name DOT identifier */

void convert_host_name (cfile, bc)
	FILE *cfile;
	jbp_decl (bc);
{
	char *val;
	int token;
	int len = 0;
	char *s;
	char *t;
	pair c = (pair)0;
	
	/* Read a dotted hostname... */
	do {
		/* Read a token, which should be an identifier. */
		token = next_token (&val, cfile);
		if (!is_identifier (token)) {
			parse_warn ("expecting an identifier in hostname");
			skip_to_semi (cfile);
			longjmp (jdref (bc), 1);
		}
		/* Spit it out... */
		fputs (val, stdout);
		/* Look for a dot; if it's there, keep going, otherwise
		   we're done. */
		token = peek_token (&val, cfile);
		if (token == DOT) {
			token = next_token (&val, cfile);
			putchar ('.');
		}
	} while (token == DOT);
}

/* class_statement :== VENDOR_CLASS STRING class_declarations SEMI
   		     | USER_CLASS class_declarations SEMI
   class_declarations :== <nil> | option_declaration
			        | option_declarations option_declaration SEMI
*/

void convert_class_statement (cfile, bc, type)
	FILE *cfile;
	jbp_decl (bc);
	int type;
{
	char *val;
	int token;
	struct class *class;

	token = next_token (&val, cfile);
	if (token != STRING) {
		parse_warn ("Expecting class name");
		skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}

	indent (0);
	if (class)
		printf ("user-class %s {\n", val);
	else
		printf ("vendor-class %s {\n", val);
	indent (2);

	do {
		token = peek_token (&val, cfile);
		if (token == SEMI) {
			token = next_token (&val, cfile);
			break;
		} else {
			convert_class_decl (cfile, bc);
		}
	} while (1);
	indent (-2);
	indent (0);
	printf ("}\n");
}

/* class_declaration :== filename_declaration
   		       | option_declaration
		       | DEFAULT_LEASE_TIME NUMBER
		       | MAX_LEASE_TIME NUMBER */

void convert_class_decl (cfile, bc)
	FILE *cfile;
	jbp_decl (bc);
{
	char *val;
	int token;

	token = next_token (&val, cfile);
	switch (token) {
	      case FILENAME:
		convert_filename_decl (cfile, bc);
		break;
	      case OPTION:
		convert_option_decl (cfile, bc);
		break;
	      default:
		parse_warn ("expecting a dhcp option declaration.");
		skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
		break;
	}
}

/* lease_time :== NUMBER */

void convert_lease_time (cfile, bc, name)
	FILE *cfile;
	jbp_decl (bc);
	char *name;
{
	char *val;
	int token;

	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("Expecting numeric lease time");
		skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
	indent (0);
	printf ("%s %s;\n", name, val);
}

/* shared_network_statement :== SHARED_NETWORK subnet_statements SEMI
   subnet_statements :== subnet_statement |
   			 subnet_statements subnet_statement */

void convert_shared_net_statement (cfile, bc)
	FILE *cfile;
	jbp_decl (bc);
{
	char *val;
	int token;
	struct shared_network *share;
	struct subnet *first_net = (struct subnet *)0;
	struct subnet *last_net = (struct subnet *)0;
	struct subnet *next_net;
	char *name;
	struct tree_cache *server_next;

	/* Get the name of the shared network... */
	token = next_token (&val, cfile);
	if (!is_identifier (token) && token != STRING) {
		skip_to_semi (cfile);
		parse_warn ("expecting shared network name");
		longjmp (jdref (bc), 1);
	}
	if (val [0] == 0) {
		parse_warn ("zero-length shared network name");
		val = "<no-name-given>";
		token = STRING;
	}

	indent (0);
	if (token == STRING)
		printf ("shared-network \"%s\" {\n", val);
	else
		printf ("shared-network %s {\n", val);
	indent (2);

	do {
		token = next_token (&val, cfile);
		switch (token) {
		      case SEMI:
			indent (-2);
			indent (0);
			printf ("}\n");
			return;

		      case SUBNET:
			convert_subnet_statement (cfile, bc);
			break;

		      case OPTION:
			convert_option_decl (cfile, bc);
			break;

		      case DEFAULT_LEASE_TIME:
			convert_lease_time (cfile, bc,
					    "default-lease-time");
			break;

		      case MAX_LEASE_TIME:
			convert_lease_time (cfile, bc,
					    "max-lease-time");
			break;

		      case DYNAMIC_BOOTP_LEASE_CUTOFF:
			convert_date (cfile, bc,
				      "dynamic-bootp-lease-cutoff");
			break;
			
		      case DYNAMIC_BOOTP_LEASE_LENGTH:
			convert_lease_time (cfile, bc,
					    "dynamic-bootp-lease-length");
			break;

		      case NEXT_SERVER:
			indent (0);
			printf ("next-server ");
			convert_ip_addr_or_hostname (cfile, bc, 0);
			printf (";\n");
			break;
			
		      case BOOT_UNKNOWN_CLIENTS:
			token = next_token (&val, cfile);
			if (token != NUMBER ||
			    (strcmp (val, "0") && strcmp (val, "1"))) {
				parse_warn ("0 or 1 expected");
				skip_to_semi (cfile);
				longjmp (jdref (bc), 1);
			}
			printf ("boot-unknown-clients %s;\n", val);
			break;

		      default:
			parse_warn ("expecting subnet declaration");
			skip_to_semi (cfile);
			longjmp (jdref (bc), 1);
		}
	} while (1);
}

/* subnet_statement :== SUBNET net NETMASK netmask declarations
   host_declarations :== <nil> | host_declaration
			       | host_declarations host_declaration SEMI */

void convert_subnet_statement (cfile, bc)
	FILE *cfile;
	jbp_decl (bc);
{
	char *val;
	int token;
	struct subnet *subnet;
	struct iaddr net, netmask;
	unsigned char addr [4];
	int len = sizeof addr;

	indent (0);
	printf ("subnet ");
	/* Get the network number... */
	convert_numeric_aggregate (cfile, bc, 4, DOT, 10, 8);

	token = next_token (&val, cfile);
	if (token != NETMASK) {
		parse_warn ("Expecting netmask");
		skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}

	printf (" netmask ");

	/* Get the netmask... */
	convert_numeric_aggregate (cfile, bc, 4, DOT, 10, 8);

	printf (" {\n");
	indent (2);

	do {
		token = peek_token (&val, cfile);
		if (token == SEMI || token == SUBNET)
			break;
		convert_subnet_decl (cfile, bc);
	} while (1);
	indent (-2);
	indent (0);
	printf ("}\n");
}

/* subnet_declaration :== hardware_declaration | filename_declaration
		        | fixed_addr_declaration | option_declaration */

void convert_subnet_decl (cfile, bc)
	FILE *cfile;
	jbp_decl (bc);
{
	char *val;
	int token;
	struct tree_cache *server_next;

	token = next_token (&val, cfile);
	switch (token) {
	      case RANGE:
		convert_address_range (cfile, bc);
		break;

	      case OPTION:
		convert_option_decl (cfile, bc);
		break;

	      case DEFAULT_LEASE_TIME:
		convert_lease_time (cfile, bc, "default-lease-time");
		break;
		
	      case MAX_LEASE_TIME:
		convert_lease_time (cfile, bc, "max-lease-time");
		break;

	      case DYNAMIC_BOOTP_LEASE_CUTOFF:
		convert_date (cfile, bc, "dynamic-bootp-lease-cutoff");
		break;
		
	      case DYNAMIC_BOOTP_LEASE_LENGTH:
		convert_lease_time (cfile, bc, "dynamic-bootp-lease-length");
		break;

	      case NEXT_SERVER:
		indent (0);
		printf ("next-server ");
		convert_ip_addr_or_hostname (cfile, bc, 0);
		break;

	      case BOOT_UNKNOWN_CLIENTS:
		token = next_token (&val, cfile);
		if (token != NUMBER ||
		    (strcmp (val, "0") && strcmp (val, "1"))) {
			parse_warn ("0 or 1 expected");
			skip_to_semi (cfile);
			longjmp (jdref (bc), 1);
		}
		indent (0);
		printf ("boot-unknown-clients %s;\n", val);
		break;

	      default:
		parse_warn ("expecting a subnet declaration.");
		skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
		break;
	}
}

/* host_declaration :== hardware_declaration | filename_declaration
		      | fixed_addr_declaration | option_declaration
		      | max_lease_declaration | default_lease_declaration */

void convert_host_decl (cfile, bc)
	FILE *cfile;
	jbp_decl (bc);
{
	char *val;
	int token;

	token = next_token (&val, cfile);
	switch (token) {
	      case HARDWARE:
		convert_hardware_decl (cfile, bc);
		break;
	      case FILENAME:
		convert_filename_decl (cfile, bc);
		break;
	      case SERVER_NAME:
		convert_servername_decl (cfile, bc);
		break;
	      case FIXED_ADDR:
		convert_fixed_addr_decl (cfile, bc);
		break;
	      case OPTION:
		convert_option_decl (cfile, bc);
		break;
	      case DEFAULT_LEASE_TIME:
		convert_lease_time (cfile, bc, "default-lease-time");
		break;
	      case MAX_LEASE_TIME:
		convert_lease_time (cfile, bc, "max-lease-time");
		break;
	      case DYNAMIC_BOOTP_LEASE_CUTOFF:
		convert_date (cfile, bc, "dynamic-bootp-lease-cutoff");
		break;
	      case DYNAMIC_BOOTP_LEASE_LENGTH:
		convert_lease_time (cfile, bc, "dynamic-bootp-lease-length");
		break;
	      case NEXT_SERVER:
		indent (0);
		printf ("next-server ");
		convert_ip_addr_or_hostname (cfile, bc, 0);
		printf (";\n");
		break;
	      default:
		parse_warn ("expecting a dhcp option declaration.");
		skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
		break;
	}
}

/* hardware_decl :== HARDWARE ETHERNET NUMBER COLON NUMBER COLON NUMBER COLON
   				       NUMBER COLON NUMBER COLON NUMBER */

void convert_hardware_decl (cfile, bc)
	FILE *cfile;
	jbp_decl (bc);
{
	indent (0);
	printf ("hardware ");
	convert_hardware_addr (cfile, bc);
	printf (";\n");
}

void convert_hardware_addr (cfile, bc)
	FILE *cfile;
	jbp_decl (bc);
{
	char *val;
	int token;
	int hlen;
	unsigned char *t;

	token = next_token (&val, cfile);
	switch (token) {
	      case ETHERNET:
		break;
#ifdef ARPHRD_IEEE802 /* XXX */
	      case TOKEN_RING:
		break;
#endif
	      default:
		parse_warn ("expecting a network hardware type");
		skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}

	fputs (val, stdout);
	putchar (' ');

	/* Parse the hardware address information.   Technically,
	   it would make a lot of sense to restrict the length of the
	   data we'll accept here to the length of a particular hardware
	   address type.   Unfortunately, there are some broken clients
	   out there that put bogus data in the chaddr buffer, and we accept
	   that data in the lease file rather than simply failing on such
	   clients.   Yuck. */
	convert_numeric_aggregate (cfile, bc, 0, COLON, 16, 8);
}

/* filename_decl :== FILENAME STRING */

void convert_filename_decl (cfile, bc)
	FILE *cfile;
	jbp_decl (bc);
{
	char *val;
	int token;

	token = next_token (&val, cfile);
	if (token != STRING) {
		parse_warn ("filename must be a string");
		skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
	indent (0);
	printf ("filename \"%s\";\n", val);
}

/* servername_decl :== SERVER_NAME STRING */

void convert_servername_decl (cfile, bc)
	FILE *cfile;
	jbp_decl (bc);
{
	char *val;
	int token;

	token = next_token (&val, cfile);
	if (token != STRING) {
		parse_warn ("server name must be a string");
		skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
	indent (0);
	printf ("server-name \"%s\";\n", val);
}

/* ip_addr_or_hostname :== ip_address | hostname
   ip_address :== NUMBER DOT NUMBER DOT NUMBER DOT NUMBER
   
   Parse an ip address or a hostname.   If uniform is zero, put in
   a TREE_LIMIT node to catch hostnames that evaluate to more than
   one IP address. */

void convert_ip_addr_or_hostname (cfile, bc, uniform)
	FILE *cfile;
	jbp_decl (bc);
	int uniform;
{
	char *val;
	int token;

	token = peek_token (&val, cfile);
	if (is_identifier (token))
		convert_host_name (cfile, bc);
	else if (token == NUMBER)
		convert_numeric_aggregate (cfile, bc, 4, DOT, 10, 8);
	else {
		parse_warn ("%s (%d): expecting IP address or hostname",
			    val, token);
		skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
}	
	

/* fixed_addr_clause :==
	FIXED_ADDR fixed_addr_decls

   fixed_addr_decls :== ip_addr_or_hostname |
   			fixed_addr_decls ip_addr_or_hostname */

void convert_fixed_addr_decl (cfile, bc)
	FILE *cfile;
	jbp_decl (bc);
{
	char *val;
	int token;

	indent (0);
	printf ("fixed-address ");
	do {
		convert_ip_addr_or_hostname (cfile, bc, 0);
		token = peek_token (&val, cfile);
		if (token == COMMA) {
			putchar (','); putchar (' ');
			token = next_token (&val, cfile);
		}
	} while (token == COMMA);
	printf (";\n");
}

/* option_declaration :== OPTION identifier DOT identifier <syntax> |
			  OPTION identifier <syntax>

   Option syntax is handled specially through format strings, so it
   would be painful to come up with BNF for it.   However, it always
   starts as above. */

void convert_option_decl (cfile, bc)
	FILE *cfile;
	jbp_decl (bc);
{
	char *val;
	int token;
	unsigned char buf [4];
	char *vendor;
	char *fmt;
	struct universe *universe;
	struct option *option;
	struct tree *tree = (struct tree *)0;

	indent (0);
	printf ("option ");
	token = next_token (&val, cfile);
	if (!is_identifier (token)) {
		parse_warn ("expecting identifier after option keyword.");
		if (token != SEMI)
			skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
	fputs (val, stdout);

	/* Look up the actual option info... */
	option = (struct option *)hash_lookup (dhcp_universe.hash, val, 0);

	token = peek_token (&val, cfile);
	if (token == DOT) {
		/* Go ahead and take the DOT token... */
		token = next_token (&val, cfile);
		putchar ('.');

		/* The next token should be an identifier... */
		token = next_token (&val, cfile);
		if (!is_identifier (token)) {
			parse_warn ("expecting identifier after '.'");
			if (token != SEMI)
				skip_to_semi (cfile);
			longjmp (jdref (bc), 1);
		}
		fputs (val, stdout);

		option = (struct option *)hash_lookup (dhcp_universe.hash,
						       val, 0);
	}

	/* If we didn't get an option structure, it's an undefined option. */
	if (!option) {
		parse_warn ("no option named %s", val);
		skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}

	/* Convert the option data... */
	do {
		/* Set a flag if this is an array of a simple type (i.e.,
		   not an array of pairs of IP addresses, or something
		   like that. */
		int uniform = option -> format [1] == 'A';

		putchar (' ');
		for (fmt = option -> format; *fmt; fmt++) {
			if (*fmt == 'A')
				break;
			switch (*fmt) {
			      case 'X':
				token = peek_token (&val, cfile);
				if (token == NUMBER_OR_ATOM ||
				    token == NUMBER) {
					do {
						token = next_token
							(&val, cfile);
						fputs (val, stdout);
						if (token == COLON) {
							token = next_token
								(&val, cfile);
							putchar (':');
						}
					} while (token == COLON);
				} else if (token == STRING) {
					token = next_token (&val, cfile);
					printf ("\"%s\"", val);
				} else {
					parse_warn ("expecting string %s.",
						    "or hexadecimal data");
					skip_to_semi (cfile);
					longjmp (jdref (bc), 1);
				}
				break;
				
			      case 't': /* Text string... */
				token = next_token (&val, cfile);
				if (token != STRING
				    && !is_identifier (token)) {
					parse_warn ("expecting string.");
					if (token != SEMI)
						skip_to_semi (cfile);
					longjmp (jdref (bc), 1);
				}
				printf ("\"%s\"", val);
				break;
				
			      case 'I': /* IP address or hostname. */
				convert_ip_addr_or_hostname (cfile, bc,
							     uniform);
				break;

			      case 'L': /* Unsigned 32-bit integer... */
			      case 'l':	/* Signed 32-bit integer... */
			      case 's':	/* Signed 16-bit integer. */
			      case 'S':	/* Unsigned 16-bit integer. */
			      case 'b':	/* Signed 8-bit integer. */
			      case 'B':	/* Unsigned 8-bit integer. */
				token = next_token (&val, cfile);
				if (token != NUMBER) {
				      need_number:
					parse_warn ("expecting number.");
					if (token != SEMI)
						skip_to_semi (cfile);
					longjmp (jdref (bc), 1);
				}
				fputs (val, stdout);
				break;
			      case 'f': /* Boolean flag. */
				token = next_token (&val, cfile);
				if (!is_identifier (token)) {
					parse_warn ("expecting identifier.");
				      bad_flag:
					if (token != SEMI)
						skip_to_semi (cfile);
					longjmp (jdref (bc), 1);
				}
				if (!strcasecmp (val, "true")
				    || !strcasecmp (val, "on"))
					;
				else if (!strcasecmp (val, "false")
					 || !strcasecmp (val, "off"))
					;
				else {
					parse_warn ("expecting boolean.");
					goto bad_flag;
				}
				fputs (val, stdout);
				break;
			      default:
				warn ("Bad format %c in parse_option_decl.",
				      *fmt);
				skip_to_semi (cfile);
				longjmp (jdref (bc), 1);
			}
		}
		if (*fmt == 'A') {
			token = peek_token (&val, cfile);
			if (token == COMMA) {
				token = next_token (&val, cfile);
				putchar (',');
				continue;
			}
			break;
		}
	} while (*fmt == 'A');
	printf (";\n");
}

/* timestamp :== TIMESTAMP date SEMI

   Timestamps are actually not used in dhcpd.conf, which is a static file,
   but rather in the database file and the journal file. */

void convert_timestamp (cfile, bc)
	FILE *cfile;
	jbp_decl (bc);
{
	TIME rv;
	char *val;
	int token;

	convert_date (cfile, bc, "timestamp");
	token = next_token (&val, cfile);
	if (token != SEMI) {
		parse_warn ("semicolon expected");
		skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
}
		
/* lease_decl :== LEASE ip_address lease_modifiers SEMI
   lease_modifiers :== <nil>
   		|	lease_modifier
		|	lease_modifier lease_modifiers
   lease_modifier :==	STARTS date
   		|	ENDS date
		|	UID hex_numbers
		|	HOST identifier
		|	CLASS identifier
		|	TIMESTAMP number
		|	DYNAMIC_BOOTP */

void convert_lease_statement (cfile, bc)
	FILE *cfile;
	jbp_decl (bc);
{
	char *val;
	int token;

	indent (0);
	printf ("lease ");

	/* Get the address for which the lease has been issued. */
	convert_numeric_aggregate (cfile, bc, 4, DOT, 10, 8);

	printf (" {\n");
	indent (2);

	do {
		token = next_token (&val, cfile);

		switch (token) {
		      case STARTS:
			convert_date (cfile, bc, "starts");
			break;
			
		      case ENDS:
			convert_date (cfile, bc, "ends");
			break;
			
		      case TIMESTAMP:
			convert_date (cfile, bc, "timestamp");
			break;
			
			/* Colon-seperated hexadecimal octets... */
		      case UID:
			indent (0);
			token = peek_token (&val, cfile);
			if (token == STRING) {
				token = next_token (&val, cfile);
				printf ("uid \"%s\";\n", val);
			} else {
				printf ("uid ");
				convert_numeric_aggregate
					(cfile, bc, 0, ':', 16, 8);
			}
			printf (";\n");
			break;

		      case HARDWARE:
			indent (0);
			printf ("hardware ");
			convert_hardware_addr (cfile, bc);
			printf (";\n");
			break;

		      case DYNAMIC_BOOTP:
			indent (0);
			printf ("dynamic-bootp;\n");
			break;

		      case SEMI:
			break;

		      default:
			skip_to_semi (cfile);
			longjmp (jdref (bc), 1);
		}
	} while (token != SEMI);
	indent (-2);
	indent (0);
	printf ("}\n");
}

/* address_range :== RANGE ip_address ip_address |
		     RANGE dynamic_bootp_statement ip_address ip_address */

void convert_address_range (cfile, bc)
	FILE *cfile;
	jbp_decl (bc);
{
	int token;
	char *val;

	indent (0);
	printf ("range ");
	if ((token = peek_token (&val, cfile)) == DYNAMIC_BOOTP) {
		token = next_token (&val, cfile);
		printf ("dynamic-bootp ");
	}

	/* Bottom address in the range... */
	convert_numeric_aggregate (cfile, bc, 4, DOT, 10, 8);
	putchar (' ');

	/* Top address in the range... */
	convert_numeric_aggregate (cfile, bc, 4, DOT, 10, 8);
	printf (";\n");
}

/* date :== NUMBER NUMBER/NUMBER/NUMBER NUMBER:NUMBER:NUMBER

   Dates are always in GMT; first number is day of week; next is
   year/month/day; next is hours:minutes:seconds on a 24-hour
   clock. */

void convert_date (cfile, bc, name)
	FILE *cfile;
	jbp_decl (bc);
	char *name;
{
	char *val;
	int token;

	indent (0);
	fputs (name, stdout);
	putchar (' ');

	/* Day of week... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric day of week expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
	fputs (val, stdout);
	putchar (' ');

	/* Year... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric year expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
	fputs (val, stdout);
	putchar ('/');

	/* Slash seperating year from month... */
	token = next_token (&val, cfile);
	if (token != SLASH) {
		parse_warn ("expected slash seperating year from month.");
		if (token != SEMI)
			skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}

	/* Month... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric month expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
	fputs (val, stdout);
	putchar ('/');

	/* Slash seperating month from day... */
	token = next_token (&val, cfile);
	if (token != SLASH) {
		parse_warn ("expected slash seperating month from day.");
		if (token != SEMI)
			skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}

	/* Month... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric day of month expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
	fputs (val, stdout);
	putchar (' ');

	/* Hour... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric hour expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
	fputs (val, stdout);
	putchar (':');

	/* Colon seperating hour from minute... */
	token = next_token (&val, cfile);
	if (token != COLON) {
		parse_warn ("expected colon seperating hour from minute.");
		if (token != SEMI)
			skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}

	/* Minute... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric minute expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
	fputs (val, stdout);
	putchar (':');

	/* Colon seperating minute from second... */
	token = next_token (&val, cfile);
	if (token != COLON) {
		parse_warn ("expected colon seperating hour from minute.");
		if (token != SEMI)
			skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}

	/* Second... */
	token = next_token (&val, cfile);
	if (token != NUMBER) {
		parse_warn ("numeric minute expected.");
		if (token != SEMI)
			skip_to_semi (cfile);
		longjmp (jdref (bc), 1);
	}
	fputs (val, stdout);
	printf (";\n");
}

/* No BNF for numeric aggregates - that's defined by the caller.  What
   this function does is to parse a sequence of numbers seperated by
   the token specified in seperator.  If max is zero, any number of
   numbers will be parsed; otherwise, exactly max numbers are
   expected.  Base and size tell us how to internalize the numbers
   once they've been tokenized. */

void convert_numeric_aggregate (cfile, bc, max, seperator, base, size)
	FILE *cfile;
	jbp_decl (bc);
	int max;
	int seperator;
	int base;
	int size;
{
	char *val;
	int token;
	int count = 0;

	do {
		if (count) {
			token = peek_token (&val, cfile);
			if (token != seperator) {
				if (!max)
					break;
				parse_warn ("too few numbers.");
				skip_to_semi (cfile);
				longjmp (jdref (bc), 1);
			}
			token = next_token (&val, cfile);
			fputs (val, stdout);
		}
		token = next_token (&val, cfile);
		/* Allow NUMBER_OR_ATOM if base is 16. */
		if (token != NUMBER &&
		    (base != 16 || token != NUMBER_OR_ATOM)) {
			parse_warn ("expecting numeric value.");
			skip_to_semi (cfile);
			longjmp (jdref (bc), 1);
		}
		fputs (val, stdout);
	} while (++count != max);
}

void indent (i)
	int i;
{
	static int indent = 0;
	int k;

	if (!i) {
		for (k = 0; k < indent / 8; k++)
			putchar ('\t');
		for (k = 0; k < indent % 8; k++)
			putchar (' ');
	} else {
		indent += i;
	}
}
