/* main.c

   DHCP Daemon controller*/

/*
 * Copyright (c) 1998 The Internet Software Consortium.
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
"$Id: dhcpctl.c,v 1.1 1998/04/09 05:20:14 mellon Exp $ Copyright (c) 1998 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

int log_priority;
int log_perror = 1;

int dhcp_max_agent_option_packet_length;

int main (argc, argv, envp)
	int argc;
	char **argv;
	char **envp;
{
	struct sockaddr_un name;
	int dhcpctl_fd;
	FILE *dhcpctl;
	int status;
	char *buf;
	int len;
	char ibuf [1024];
	int arg;

#ifdef SYSLOG_4_2
	openlog ("statmsg", LOG_NDELAY);
	log_priority = LOG_DAEMON;
#else
	openlog ("statmsg", LOG_NDELAY, LOG_DAEMON);
#endif

#if !(defined (DEBUG) || defined (SYSLOG_4_2) || defined (__CYGWIN32__))
	setlogmask (LOG_UPTO (LOG_INFO));
#endif	

	dhcpctl_fd = socket (AF_UNIX, SOCK_STREAM, 0);
	if (dhcpctl_fd < 0)
		error ("unable to create dhcpctl socket: %m");

	/* XXX for now... */
	name.sun_family = PF_UNIX;
	strcpy (name.sun_path, "/var/run/dhcpctl");
#if defined (HAVE_SA_LEN)
	name.sun_len = 
#endif
		len = ((sizeof name) - (sizeof name.sun_path) +
		       strlen (name.sun_path));

	if (connect (dhcpctl_fd, (struct sockaddr *)&name, len) < 0)
		error ("can't connect to dhcpctl socket: %m");

#if 0
	if ((arg = fcntl (dhcpctl_fd, F_GETFL, 0)) < 0)
		error ("Can't get flags on socket: %m");
	arg |= O_ASYNC;
	if (fcntl (dhcpctl_fd, F_SETFL, arg) < 0)
		error ("Can't set flags on socket: %m");
#endif

	dhcpctl = fdopen (dhcpctl_fd, "r+");
	if (!dhcpctl)
		error ("Can't fdopen dhcpctl socket: %m");
	setlinebuf (dhcpctl);

	/* Read the response. */
	while (fgets (ibuf, sizeof ibuf, stdin)) {
		len = strlen (ibuf);
		if (!len)
			break;
		fputs (ibuf, dhcpctl);
		fflush (dhcpctl);
		if (ibuf [len - 1] != '\n')
			putc ('\n', dhcpctl);

		while (fgets (ibuf, sizeof ibuf, dhcpctl)) {
			if (ibuf [0] == '-') {
				fputs (&ibuf [1], stdout);
			} else {
				fputs (ibuf, stdout);
				break;
			}
			fflush (stdout);
		}
	}

	exit (0);
}

void cleanup ()
{
}
