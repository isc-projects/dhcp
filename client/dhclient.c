/* dhclient.c

   DHCP client program.   Intended for testing. */

/*
 * Copyright (c) 1996 The Internet Software Consortium.  All rights reserved.
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

#include "dhcpd.h"
#include "dhctoken.h"

TIME cur_time;

int main (argc, argv, envp)
	int argc;
	char **argv;
	char **envp;
{
	FILE *cfile = stdin;
	char *val;
	int token;

	/* Set up the initial dhcp option universe. */
	initialize_universes ();

	/* Get the current time... */
	GET_TIME (&cur_time);

	do {
		token = peek_token (&val, cfile);
		if (token == EOF)
			break;
		parse_client_statement (cfile);
	} while (1);
	exit (0);
}

/* statement :== host_statement */

void parse_client_statement (cfile)
	FILE *cfile;
{
	char *val;
	jmp_buf bc;
	struct host_decl decl;
	int token;
	struct dhcp_packet raw;
	struct packet outpacket, inpacket;
	int i;

	switch (next_token (&val, cfile)) {
	      case PACKET:
		memset (&decl, 0, sizeof decl);
		if (!setjmp (bc)) {
			do {
				token = peek_token (&val, cfile);
				if (token == SEMI) {
					token = next_token (&val, cfile);
					break;
				}
				parse_host_decl (cfile, &bc, &decl);
			} while (1);
		}
		for (i = 0; i < 256; i++)
			if (decl.options [i])
				printf ("option %s\n", dhcp_options [i].name);
		memset (&outpacket, 0, sizeof outpacket);
		memset (&raw, 0, sizeof raw);
		outpacket.raw = &raw;
		cons_options ((struct packet *)0, &outpacket, &decl, 3);
		inpacket.raw = &raw;
		inpacket.packet_length = outpacket.packet_length;
		parse_options (&inpacket);
		for (i = 0; i < 256; i++)
			if (inpacket.options [i].len)
				printf ("%s=%s\n",
					dhcp_options [i].name,
					pretty_print_option
					(i,
					 inpacket.options [i].data,
					 inpacket.options [i].len));
		for (i = 0; i < 20; i++)
			printf ("%s%x", i == 0 ? "" : " ",
				(unsigned char)raw.options [i]);
		printf ("\noptions_valid: %d\n", inpacket.options_valid);
		break;
	      default:
		parse_warn ("expecting a declaration.");
		skip_to_semi (cfile);
		break;
	}
}

void cleanup ()
{
}
