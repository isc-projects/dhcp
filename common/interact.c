/* interact.c

   Text interactor for dhcp servers. */

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
 * This software was written for the Internet Software Consortium by
 * Ted Lemon <mellon@fugue.com> in cooperation with Vixie Enterprises.
 * To learn more about the Internet Software Consortium, see
 * ``http://www.vix.com/isc''.  To learn more about Vixie Enterprises,
 * see ``http://www.vix.com''.
 */

#ifndef lint
static char copyright[] =
"$Id: interact.c,v 1.2 1999/02/24 17:56:45 mellon Exp $ Copyright (c) 1998 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

int interact_initialized;
int interact_fd;
static struct interact_client *interact_clients;

void interact_startup ()
{
	struct sockaddr_un name;
	static int once;
	int len;
	mode_t m;

	/* Only initialize interact once. */
	if (interact_initialized)
		log_fatal ("attempted to reinitialize interact protocol");
	interact_initialized = 1;

	/* Make a socket... */
	interact_fd = socket (AF_UNIX, SOCK_STREAM, 0);
	if (interact_fd < 0)
		log_fatal ("unable to create interact socket: %m");

	/* XXX for now... */
	name.sun_family = PF_UNIX;
	strcpy (name.sun_path, "/var/run/dhcpctl");
#if defined (HAVE_SA_LEN)
	name.sun_len =
#endif
		len = ((sizeof name) - (sizeof name.sun_path) +
		       strlen (name.sun_path));
	unlink (name.sun_path);

	/* interact socket should be accessible only by root. */
	m = umask (0700);

	/* Bind to it... */
	if (bind (interact_fd, (struct sockaddr *)&name, len) < 0) {
		log_error ("can't bind to interact socket: %m");
		close (interact_fd);
		umask (m);
		return;
	}
	umask (m);

	/* Listen for connections... */
	if (listen (interact_fd, 1) < 0) {
		log_error ("can't listen on interact socket: %m");
		close (interact_fd);
		unlink (name.sun_path);
		return;
	}

	add_protocol ("interact", interact_fd, new_interact_connection, 0);
}

void new_interact_connection (proto)
	struct protocol *proto;
{
	struct sockaddr_un name;
	int namelen;
	struct interact_client *tmp;
	int new_fd;
	int arg;

	tmp = (struct interact_client *)malloc (sizeof *tmp);
	if (!tmp)
		log_fatal ("Can't find memory for new client!");
	memset (tmp, 0, sizeof *tmp);

	namelen = sizeof name;
	new_fd = accept (proto -> fd, (struct sockaddr *)&name, &namelen);
	if (new_fd < 0) {
		log_error ("accept: %m");
		free (tmp);
		return;
	}

	if ((arg = fcntl (new_fd, F_GETFL, 0)) < 0) {
	bad_flag:
		log_error ("Can't set flags on new interactive client: %m");
		close (new_fd);
		free (tmp);
		return;
	}
	arg |= O_NONBLOCK;
	if (fcntl (new_fd, F_SETFL, arg) < 0)
		goto bad_flag;

	tmp -> next = interact_clients;
	tmp -> fd = new_fd;
	interact_clients = tmp;
	tmp -> cur_node_actions = top_level_actions;

	tmp -> proto = add_protocol ("aclient", new_fd,
				     interact_client_input, tmp);
}

void interact_client_input (proto)
	struct protocol *proto;
{
	int status;
	char *eobuf;
	struct interact_client *client = proto -> local;

	status = read (proto -> fd, &client -> ibuf [client -> ibuflen],
		       (sizeof client -> ibuf) - client -> ibuflen);
	if (status < 0) {
		log_error ("interact_client_input: %m");
	blow:
		close (proto -> fd);
		remove_protocol (proto);
		free (client);
		return;
	}
	/* EOF: get lost. */
	if (status == 0)
		goto blow;

	client -> ibuflen += status;
	eobuf = memchr (client -> ibuf, '\n', client -> ibuflen);
	if (!eobuf) {
		if (client -> ibuflen == sizeof client -> ibuf) {
			log_error ("interact_client_input: buffer overflow.");
			goto blow;
		}
		return;
	}

	/* NUL terminate and blow away newline. */
	*eobuf = 0;

	if (!strcmp (client -> ibuf, "ls"))
		(*client -> cur_node_actions.ls) (client);
	else if (!strncmp (client -> ibuf, "print ", 6))
		(*client -> cur_node_actions.print) (client,
							&client -> ibuf [6]);
	else if (!strncmp (client -> ibuf, "set ", 4))
		(*client -> cur_node_actions.set) (client,
						      &client -> ibuf [4]);
	else if (!strncmp (client -> ibuf, "rm ", 3))
		(*client -> cur_node_actions.rm) (client,
						     &client -> ibuf [3]);
	else if (!strcmp (client -> ibuf, "cd .."))
		(*client -> cur_node_actions.cdup) (client);
	else if (!strncmp (client -> ibuf, "cd ", 3))
		(*client -> cur_node_actions.cd) (client,
						     &client -> ibuf [3]);
	else if (!strcmp (client -> ibuf, "exit")) {
		interact_client_write (client, "done.", 1);
		goto blow;
	} else
		interact_client_write (client, "invalid command", 1);

	/* In case the client wrote more than one command. */
	if (client -> ibuflen -= eobuf - &client -> ibuf [0] + 1)
		memmove (client -> ibuf, eobuf, client -> ibuflen);
}

int interact_client_write (client, string, lastp)
	struct interact_client *client;
	char *string;
	int lastp;
{
	static char *obuf;
	static int obufmax;
	char *bp;

	/* Unlikely to loop, but why not be sure? */
	if (obufmax < strlen (string)) {
		if (obuf)
			free (obuf);
		obufmax = (strlen (string) + 1025) & ~1023;
		obuf = malloc (obufmax);
		if (!obuf) {
			log_error ("interact_client_write: out of memory");
		blow:
			close (client -> proto -> fd);
			remove_protocol (client -> proto);
			free (client);
			return 0;
		}
	}

	bp = obuf;
	if (!lastp)
		*bp++ = '-';
	strcpy (bp, string);
	bp += strlen (bp);
	*bp++ = '\n';
	if (write (client -> fd, obuf, bp - obuf) < 0)
		return 0;

	return 1;
}
