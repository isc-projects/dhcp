/* print.c

   Turn data structures into printable text. */

/*
 * Copyright (c) 1995 The Internet Software Consortium.  All rights reserved.
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
"@(#) Copyright (c) 1995 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

char *print_hw_addr (htype, hlen, data)
	int htype;
	int hlen;
	unsigned char *data;
{
	static char habuf [49];
	char *s;
	int i;

	if (htype == 0 || hlen == 0) {
		strcpy (habuf, "<null>");
	} else {
		s = habuf;
		for (i = 0; i < hlen; i++) {
			sprintf (s, "%x", data [i]);
			s += strlen (s);
			*s++ = ':';
		}
		*--s = 0;
	}
	return habuf;
}

void print_lease (lease)
	struct lease *lease;
{
	struct tm *t;
	char tbuf [32];

	printf ("  Lease %s",
		piaddr (lease -> ip_addr));
	
	t = gmtime (&lease -> starts);
	strftime (tbuf, sizeof tbuf, "%D %H:%M:%S", t);
	printf ("  start %s", tbuf);
	
	t = gmtime (&lease -> ends);
	strftime (tbuf, sizeof tbuf, "%D %H:%M:%S", t);
	printf ("  end %s", tbuf);
	
	t = gmtime (&lease -> timestamp);
	strftime (tbuf, sizeof tbuf, "%D %H:%M:%S", t);
	printf ("  stamp %s\n", tbuf);
	
	printf ("    hardware addr = %s",
		print_hw_addr (lease -> hardware_addr.htype,
			       lease -> hardware_addr.hlen,
			       lease -> hardware_addr.haddr));
	printf ("  host %s  state %x\n",
		lease -> host ? lease -> host -> name : "<none>",
		lease -> state);
}	

void dump_packet (tp)
	struct packet *tp;
{
	struct dhcp_packet *tdp = tp -> raw;

	debug ("op = %d  htype = %d  hlen = %d  hops = %d",
	       tdp -> op, tdp -> htype, tdp -> hlen, tdp -> hops);
	debug ("xid = %x  secs = %d  flags = %x",
	       tdp -> xid, tdp -> secs, tdp -> flags);
	debug ("ciaddr = %s  yiaddr = %s",
	       inet_ntoa (tdp -> ciaddr), inet_ntoa (tdp -> yiaddr));
	debug ("siaddr = %s  giaddr = %s",
	       inet_ntoa (tdp -> siaddr), inet_ntoa (tdp -> giaddr));
	debug ("chaddr = %02.2x:%02.2x:%02.2x:%02.2x:%02.2x:%02.2x",
	       ((unsigned char *)(tdp -> chaddr)) [0],
	       ((unsigned char *)(tdp -> chaddr)) [1],
	       ((unsigned char *)(tdp -> chaddr)) [2],
	       ((unsigned char *)(tdp -> chaddr)) [3],
	       ((unsigned char *)(tdp -> chaddr)) [4],
	       ((unsigned char *)(tdp -> chaddr)) [5]);
	debug ("filename = %s\n", tdp -> file);
	debug ("server_name = %s\n", tdp -> sname);
	if (tp -> options_valid) {
		int i;

		for (i = 0; i < 256; i++) {
			if (tp -> options [i].data)
				printf ("  %s = %s\n",
					dhcp_options [i].name,
					pretty_print_option
					(i, tp -> options [i].data,
					 tp -> options [i].len));
		}
	}
}

