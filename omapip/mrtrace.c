/* mrtrace.c

   Subroutines that support minires tracing... */

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
 * by Ted Lemon, as part of a project for Nominum, Inc.   To learn more
 * about the Internet Software Consortium, see http://www.isc.org/.  To
 * learn more about Nominum, Inc., see ``http://www.nominum.com''.
 */

#include <omapip/omapip_p.h>

#include "minires/minires.h"
#include "arpa/nameser.h"

#if defined (TRACING)
static void trace_mr_output_input (trace_type_t *, unsigned, char *);
static void trace_mr_output_stop (trace_type_t *);
static void trace_mr_input_input (trace_type_t *, unsigned, char *);
static void trace_mr_input_stop (trace_type_t *);
static void trace_mr_statp_input (trace_type_t *, unsigned, char *);
static void trace_mr_statp_stop (trace_type_t *);
trace_type_t *trace_mr_output;
trace_type_t *trace_mr_input;
trace_type_t *trace_mr_statp;
ssize_t trace_mr_send (int, void *, size_t, int);
ssize_t trace_mr_read_playback (void *, size_t);
void trace_mr_read_record (void *, ssize_t);
ssize_t trace_mr_recvfrom (int s, void *, size_t, int,
			   struct sockaddr *, socklen_t *);
ssize_t trace_mr_read (int, void *, size_t);
int trace_mr_connect (int s, const struct sockaddr *, socklen_t);
int trace_mr_socket (int, int, int);
int trace_mr_bind (int, const struct sockaddr *, socklen_t);
int trace_mr_close (int);
time_t trace_mr_time (time_t *);
int trace_mr_select (int, fd_set *, fd_set *, fd_set *, struct timeval *);

extern time_t cur_time;

void trace_mr_init ()
{
	trace_mr_output = trace_type_register ("mr-output", (void *)0,
					       trace_mr_output_input,
					       trace_mr_output_stop, MDL);
	trace_mr_input = trace_type_register ("mr-input", (void *)0,
					      trace_mr_input_input,
					      trace_mr_input_stop, MDL);
	trace_mr_statp = trace_type_register ("mr-statp", (void *)0,
					      trace_mr_statp_input,
					      trace_mr_statp_stop, MDL);
}

void trace_mr_statp_setup (res_state statp)
{
	unsigned buflen = 0;
	char *buf = (char *)0;
	isc_result_t status;

	if (trace_playback ()) {
		int nscount;
		status = trace_get_packet (&trace_mr_statp, &buflen, &buf);
		if (status != ISC_R_SUCCESS) {
			log_error ("trace_mr_statp: no statp packet found.");
			return;
		}
		nscount = buflen / sizeof (struct sockaddr_in);
		if (nscount * (sizeof (struct sockaddr_in)) != buflen) {
			log_error ("trace_mr_statp: bogus length: %d",
				   buflen);
			return;
		}
		if (nscount > MAXNS)
			nscount = MAXNS;
		memcpy (statp, buf, nscount * sizeof (struct sockaddr_in));
		dfree (buf, MDL);
		buf = (char *)0;
	}
	if (trace_record ()) {
	    trace_write_packet (trace_mr_statp,
				statp -> nscount * sizeof (struct sockaddr_in),
				(char *)statp -> nsaddr_list, MDL);
	}
}


ssize_t trace_mr_send (int fd, void *msg, size_t len, int flags)
{
	if (trace_record ())
		trace_write_packet (trace_mr_output, len, msg, MDL);
	return send (fd, msg, len, flags);
}

ssize_t trace_mr_read_playback (void *buf, size_t nbytes)
{
	isc_result_t status;
	unsigned buflen = 0;
	char *inbuf = (char *)0;
	u_int32_t result;
	ssize_t rv;

	status = trace_get_packet (&trace_mr_input, &buflen, &inbuf);
	if (status != ISC_R_SUCCESS) {
		log_error ("trace_mr_recvfrom: no input found.");
		errno = ECONNREFUSED;
		return -1;
	}
	if (buflen < sizeof result) {
		log_error ("trace_mr_recvfrom: data too short.");
		errno = ECONNREFUSED;
		dfree (buf, MDL);
		return -1;
	}
	memcpy (&result, inbuf, sizeof result);
	result = ntohl (result);
	if (result == 0) {
		rv = buflen - sizeof result;
		if (rv > nbytes) {
			log_error ("trace_mr_recvfrom: too much%s",
				   " data.");
			errno = ECONNREFUSED;
			dfree (buf, MDL);
			return -1;
		}
		memcpy (buf, inbuf, (unsigned)rv);
		return rv;
	}
	errno = ECONNREFUSED;
	return -1;
}

void trace_mr_read_record (void *buf, ssize_t rv)
{
	trace_iov_t iov [2];
	u_int32_t result;
	
	result = htonl (rv);
	iov [0].buf = (char *)&result;
	iov [0].len = sizeof result;
	if (rv > 0) {
		iov [1].buf = buf;
		iov [1].len = rv;
	}
	trace_write_packet_iov (trace_mr_input,
				rv > 0 ? 2 : 1, iov, MDL);
}

ssize_t trace_mr_recvfrom (int s, void *buf, size_t len, int flags,
			   struct sockaddr *from, socklen_t *fromlen)
{
	ssize_t rv;

	if (trace_playback ()) {
		trace_mr_read_playback (buf, len);
	} else {
		rv = recvfrom (s, buf, len, flags, from, fromlen);
		if (trace_record ()) {
			trace_mr_read_record (buf, rv);
		}
	}
	return rv;
}

ssize_t trace_mr_read (int d, void *buf, size_t nbytes)
{
	ssize_t rv;

	if (trace_playback ()) {
		trace_mr_read_playback (buf, nbytes);
	} else {
		rv = read (d, buf, nbytes);
		if (trace_record ()) {
			trace_mr_read_record (buf, rv);
		}
	}
	return rv;
}

int trace_mr_connect (int s, const struct sockaddr *name, socklen_t namelen)
{
	if (!trace_playback ())
		return connect (s, name, namelen);
	return 1000;
}

int trace_mr_socket (int domain, int type, int protocol)
{
	if (!trace_playback ())
		return socket (domain, type, protocol);
	return 1000;
}

int trace_mr_bind (int s, const struct sockaddr *name, socklen_t namelen)
{
	if (!trace_playback ())
		return bind (s, name, namelen);
	return 0;
}

int trace_mr_close (int s)
{
	if (!trace_playback ())
		return close (s);
	return 0;
}

time_t trace_mr_time (time_t *tp)
{
	if (trace_playback ()) {
		if (tp)
			*tp = cur_time;
		return cur_time;
	}
	return time (tp);
}

int trace_mr_select (int s, fd_set *r, fd_set *w, fd_set *x, struct timeval *t)
{
	if (trace_playback ()) {
		time_t nct = trace_snoop_time ();
		time_t secr = t -> tv_sec;
		t -> tv_sec = nct - cur_time;
		if (t -> tv_sec > secr)
			return 0;
		return 1;
	}
	return select (s, r, w, x, t);
}

static void trace_mr_output_input (trace_type_t *ttype,
				   unsigned length, char *buf)
{
}

static void trace_mr_output_stop (trace_type_t *ttype)
{
}

static void trace_mr_input_input (trace_type_t *ttype,
				  unsigned length, char *buf)
{
	log_error ("unaccounted-for minires input.");
}

static void trace_mr_input_stop (trace_type_t *ttype)
{
}

static void trace_mr_statp_input (trace_type_t *ttype,
				  unsigned length, char *buf)
{
	log_error ("unaccounted-for minires statp input.");
}

static void trace_mr_statp_stop (trace_type_t *ttype)
{
}


#endif
