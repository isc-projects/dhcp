/* dhclient.c

   DHCP Client (less lame DHCP client). */

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
 *
 * This client was substantially modified and enhanced by Elliot Poger
 * while he was working on the MosquitoNet project at Stanford.
 */

#ifndef lint
static char copyright[] =
"$Id: dhclient.c,v 1.22 1997/01/02 12:00:14 mellon Exp $ Copyright (c) 1995, 1996 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

TIME cur_time;
TIME default_lease_time = 43200; /* 12 hours... */
TIME max_lease_time = 86400; /* 24 hours... */
struct tree_cache *global_options [256];

struct iaddr server_identifier;
int server_identifier_matched;
int log_perror = 1;

const u_long broadcast_address = INADDR_BROADCAST;
const int max_retransmissions = 4;
const int min_delay = 4;

/* Globals for the real_dhcp_client state machine. */
TIME lease_expiry, T1_expiry, T2_expiry;
struct packet *sendpacket;
struct packet *recvpacket;
struct packet *leasepacket;
int sendpacket_flag, recvpacket_flag;
u_long destination;

enum {
	S_INIT, S_SELECTING, S_REQUESTING, 
	S_BOUND, S_RENEWING, S_REBINDING
} state;

/* ASSERT_STATE() does nothing now; it used to be 
 * assert(state_is==state_shouldbe); */
#define ASSERT_STATE(state_is, state_shouldbe) {}

int retransmissions_left, retransmission_delay;
struct interface_info *dhclient_interface;

 
#ifdef USE_FALLBACK
struct interface_info fallback_interface;
#endif

u_int16_t server_port;
int log_priority;

int lexline, lexchar;
char *tlname, *token_line;

static void usage PROTO ((void));

int main (argc, argv, envp)
	int argc;
	char **argv, **envp;
{
	int i;
	struct servent *ent;
	struct interface_info *interface;

#ifdef SYSLOG_4_2
	openlog ("dhclient", LOG_NDELAY);
	log_priority = LOG_DAEMON;
#else
	openlog ("dhclient", LOG_NDELAY, LOG_DAEMON);
#endif

#ifndef	NO_PUTENV
	/* ensure mktime() calls are processed in UTC */
	putenv("TZ=GMT0");
#endif /* !NO_PUTENV */

#if !(defined (DEBUG) || defined (SYSLOG_4_2))
	setlogmask (LOG_UPTO (LOG_INFO));
#endif	

	for (i = 1; i < argc; i++) {
		if (!strcmp (argv [i], "-p")) {
			if (++i == argc)
				usage ();
			server_port = htons (atoi (argv [i]));
			debug ("binding to user-specified port %d",
			       ntohs (server_port));
 		} else if (argv [i][0] == '-') {
 		    usage ();
 		} else {
 		    struct interface_info *tmp =
 			((struct interface_info *)
 			 dmalloc (sizeof *tmp, "specified_interface"));
 		    if (!tmp)
 			error ("Insufficient memory to %s %s",
 			       "record interface", argv [i]);
 		    memset (tmp, 0, sizeof *tmp);
 		    strcpy (tmp -> name, argv [i]);
 		    tmp -> next = interfaces;
 		    tmp -> flags = INTERFACE_REQUESTED;
 		    interfaces = tmp;
 		}
	}
	/* Default to the DHCP/BOOTP port. */
	if (!server_port) {
		ent = getservbyname ("dhcpc", "udp");
		if (!ent)
			server_port = htons (68);
		else
			server_port = ent -> s_port;
		endservent ();
	}
  
	/* Get the current time... */
	GET_TIME (&cur_time);

	/* Discover all the network interfaces and initialize them. */
	discover_interfaces (0);

	/* This is a real DHCP client!
	 * SO, fork off a dhclient state machine for each
	 * interface. */
	for (dhclient_interface = interfaces; dhclient_interface; 
	     dhclient_interface = dhclient_interface -> next) {
		if (!dhclient_interface -> next || fork() == 0) {
			srandom(cur_time + *(int *)
				&dhclient_interface->hw_address.haddr);
			dhclient_state_machine();
			dhclient_fail();
		}
	}

	return 0;
}

/* This routine should be called when the DHCP client quits for any reason.
 * It makes the interface unusable and outputs an error message before
 * exiting.  A warn() message should be given first for specific errors. */

void dhclient_fail()
{
	disable_interface(dhclient_interface);
	error ("dhclient for '%s' halted",
	       dhclient_interface->name);
}

/* Handles the KILL signal for this DHCP client process.
 * Sends a DHCPRELEASE message to the server (to be a good neighbor) before
 * calling failure routine. */
void handle_kill(dummy)
     int dummy;
{
	warn("dhclient has been killed!");
	/* XXX figure out whether the lease has expired... */
	if (leasepacket -> packet_type == DHCPACK) {
		warn("sending DHCPRELEASE");
		send_release(leasepacket);
	}
	dhclient_fail ();
}

/* Make this network interface unusable by most programs.  This routine is
 * called whenever dhclient discovers this host holds no lease.
 * dhclient must still be able to use it, though, so we can get a lease!!!
 * Just remove all the routes to this interface, and set its IP address to 
 * 0.0.0.0.  dhclient will have to find some way to communicate with it. */
void disable_interface(interface)
     struct interface_info *interface;
{
	struct in_addr zero_addr;

	remove_all_if_routes (interface);
	zero_addr.s_addr = 0;
	set_ip_address (interface, zero_addr);
}

void apply_parameters(interface, packet)
     struct interface_info *interface;
     struct packet *packet;
{
	struct in_addr net_addr, tmp;

	/* Eventually, set IP address, netmask, router, DNS servers, 
	 * domain name, broadcast addr, etc.
	 *
	 * For now, set IP addr, netmask, and broadcast addr, add gateway,
	 * and update routes.
	 * Call OS-dependent routines to do the dirty work.
	 */
	
	note("Setting parameters for %s interface...", interface->name);
		
	remove_all_if_routes (interface);
	set_ip_address (interface, packet -> raw -> yiaddr);

	memcpy (&tmp, packet->options[DHO_SUBNET_MASK].data, sizeof tmp);
	set_netmask (interface, tmp);

	memcpy (&tmp, packet->options[DHO_BROADCAST_ADDRESS].data, sizeof tmp);
	set_broadcast_addr(interface, tmp);

	/* network addr = (my IP addr) AND (netmask) */
	memcpy (&tmp, packet -> options[DHO_SUBNET_MASK].data, sizeof tmp);
	net_addr.s_addr = packet -> raw -> yiaddr.s_addr & tmp.s_addr;
	memcpy (&tmp, packet->options[DHO_SUBNET_MASK].data, sizeof tmp);
	add_route_net(interface, net_addr, tmp);

	memcpy (&tmp, packet->options[DHO_ROUTERS].data, sizeof tmp);
	add_route_default_gateway(interface, tmp);
}

static void usage ()
{
	error ("Usage: dhclient [-c] [-p <port>] [interface]");
}

void cleanup ()
{
}

/* The state machine for a true DHCP client, on one particular interface
 * (stored in global dhclient_interface).
 * This function should not be exited except on a fatal error. */
void dhclient_state_machine ()
{
	fd_set read_fd;
	struct timeval tv, timeout;
	int reset_timer_flag;
	long int rnd;

	recvpacket = new_packet("recvpacket");
	recvpacket->raw = new_dhcp_packet("recvpacket->raw");
	sendpacket = new_packet("sendpacket");
	sendpacket->raw = new_dhcp_packet("sendpacket->raw");
	leasepacket = new_packet("leasepacket");
	leasepacket->raw = new_dhcp_packet("leasepacket->raw");

	/* Figure out when we time out... */
	gettimeofday (&timeout, (struct timezone *)0);
	timeout.tv_sec++;

	state = S_INIT;
	sendpacket_flag = 0;
	recvpacket_flag = 0;
	retransmissions_left = 0;

	signal(SIGTERM, handle_kill);
	signal(SIGINT, handle_kill);
	while (1) {
		/* We have awakened for some reason.  Possible reasons are:
		 * -> just entered INIT state (special case)
		 * -> packet received on this port (recvbuffer != NULL)
		 * -> timeout  (we may want to retransmit a request)
		 */
		GET_TIME (&cur_time);
		sendpacket_flag = 0;

		if (state == S_INIT) {
			reset_timer_flag = state_init();
		} else if ( (!recvpacket_flag) && (retransmissions_left>0) ) {
			/* Timed out; retransmit. */
			retransmissions_left--;
			retransmission_delay = retransmission_delay*2;
			reset_timer_flag = 1;
			sendpacket_flag = 1;
		} else {
			/* Either a packet was received 
			 * or we timed out and ran out of retransmissions.
			 */
			if (recvpacket_flag) {
				read_packet(dhclient_interface, recvpacket);
			}			
			/* If a packet was received, first check to make
			 * sure it's relevant to our last request; if it's
			 * not, ignore it and go back to sleep.
			 */
			if ((recvpacket_flag) && 
			    ((!recvpacket->options_valid) ||
			     (recvpacket->raw->op != BOOTREPLY) ||
			     (recvpacket->raw->xid!=sendpacket->raw->xid) ) ) {
				reset_timer_flag = 0;
			} else {
				note ("%s for %s",
				      (recvpacket -> packet_type == 0
				       ? "BOOTREPLY" :
				       (recvpacket -> packet_type == DHCPOFFER
					? "DHCPOFFER" :
					(recvpacket -> packet_type == DHCPACK
					 ? "DHCPACK" :
					 (recvpacket -> packet_type == DHCPNAK
					  ? "DHCPNAK" : "DHCP Unknown")))),
				      inet_ntoa (recvpacket -> raw -> yiaddr));

				/* Call the appropriate routine for this state.
				 * This routine handles both timeout 
				 * and packet-received cases.
				 *
				 * The routine returns 1 if the select()
				 * timer should be reset (which is ALWAYS the
				 * case when sending a new packet).
				 * Otherwise, we just continue our last select.
				 */
				switch (state) {
				case S_SELECTING:
					reset_timer_flag = state_selecting();
					break;
				case S_REQUESTING:
					reset_timer_flag = state_requesting();
					break;
				case S_BOUND:
					reset_timer_flag = state_bound();
					break;
				case S_RENEWING:
					reset_timer_flag = state_renewing();
					break;
				case S_REBINDING:
					reset_timer_flag = state_rebinding();
					break;
				default:
					warn("dhclient entered bad state");
					dhclient_fail();
				}
			}	
		}			

		/* Send a packet and reset the timer OR
		 * set a new timer with no outstanding request OR
		 * just go back to sleep because we're still waiting for
		 * something. */
		if (reset_timer_flag) {
			if (sendpacket_flag) {
				send_packet_struct(dhclient_interface, 
						   destination, sendpacket); 
			}
			rnd = random();
			tv.tv_sec = retransmission_delay - 1 + (rnd&1);
			tv.tv_usec = rnd % 1000000;
			gettimeofday (&timeout, (struct timezone *)0);
			timeout.tv_usec += tv.tv_usec;
			if (timeout.tv_usec > 1000000) {
				timeout.tv_usec -= 1000000;
				timeout.tv_sec++;
			}
			timeout.tv_sec += tv.tv_sec;
		} else {
			gettimeofday (&tv, (struct timezone *)0);
			tv.tv_usec = timeout.tv_usec - tv.tv_usec;
			if (tv.tv_usec < 0) {
				tv.tv_usec += 1000000;
				tv.tv_sec--;
			}
			tv.tv_sec = timeout.tv_sec - tv.tv_sec;
			if (tv.tv_sec < 0) {
				warn ("timer expired unexpectedly!");
				dhclient_fail ();
			}
		}

		FD_ZERO (&read_fd);
		FD_SET  (dhclient_interface->rfdesc, &read_fd);
		recvpacket_flag = select(dhclient_interface->rfdesc+1, 
					 &read_fd, NULL, NULL, &tv);
		if (recvpacket_flag < 0) {
			warn ("select: %m");
			dhclient_fail();
		}
	}
	/* keep cycling through the state machine until dhclient_fail() */
}

/* Individual States:
 * 
 * Each routine is called from the dhclient_state_machine() in one of
 * these conditions:
 * -> entering INIT state
 * -> recvpacket_flag == 0: timeout in this state
 * -> otherwise: received a packet in this state
 *
 * Return conditions as handled by dhclient_state_machine():
 * Returns 1, sendpacket_flag = 1: send packet, reset timer.
 * Returns 1, sendpacket_flag = 0: just reset the timer (wait for a milestone).
 * Returns 0: finish the nap which was interrupted for no good reason.
 *
 * Several global variables are used to keep track of the process:
 *   recvpacket: most recent packet received
 *   sendpacket: most recent packet sent or to be sent
 *   leasepacket: copy of most recent valid lease DHCPACK packet
 *   recvpacket_flag: recvpacket is not old hat
 *   sendpacket_flag: sendpacket is to be sent
 *   destination: IP address to send sendpacket to
 *   retransmissions_left: # of times remaining to resend this sendpacket
 *   retransmission_delay: # of seconds to wait before next retransmission
 *   T1_expiry, T2_expiry, lease_expiry: lease milestones
 */

int state_init()
{
	ASSERT_STATE(state, S_INIT);

	/* Don't let anyone else use this interface until we get a lease,
	 * but make sure we can use it to obtain a lease! */
	disable_interface(dhclient_interface);
	if_enable (dhclient_interface);

	make_discover(dhclient_interface, sendpacket);
	sendpacket_flag = 1;
	retransmissions_left = max_retransmissions;
	retransmission_delay = min_delay;
	destination = broadcast_address;
	state = S_SELECTING;
	return 1;
}

int state_selecting()
{
	ASSERT_STATE(state, S_SELECTING);

	if (!recvpacket_flag) {
		warn("no DHCP server found");
		dhclient_fail();
		/*NOTREACHED*/
		return 0;
	} else if (recvpacket->packet_type != DHCPOFFER) {
		return 0; /* wait for a DHCPOFFER */
	} else {
		/* Got a DHCPOFFER! */
		make_request(recvpacket, sendpacket);
		sendpacket->raw->xid = random();
		sendpacket_flag = 1;
		destination = broadcast_address;
		retransmissions_left = max_retransmissions;
		retransmission_delay = min_delay;
		state = S_REQUESTING;
		return 1;
	}
}  

int state_requesting()
{
	ASSERT_STATE(state, S_REQUESTING);

	if (!recvpacket_flag) {
		warn("lost contact with DHCP server");
		state = S_INIT;
		return state_init();
	} else if (recvpacket->packet_type == DHCPNAK) {
		warn("DHCPOFFER withdrawn");
		state = S_INIT;
		return state_init();
	} else if (recvpacket->packet_type == DHCPACK) {
		/* We got a lease!  Apply its parameters,
		 * record lease info, and set timer to T1. */
		deep_packet_copy(leasepacket, recvpacket);
		apply_parameters(dhclient_interface, leasepacket);
		lease_expiry = abs_time(leasepacket, DHO_DHCP_LEASE_TIME);
		T1_expiry = abs_time(leasepacket, DHO_DHCP_RENEWAL_TIME);
		T2_expiry = abs_time(leasepacket, DHO_DHCP_REBINDING_TIME);
		retransmissions_left = 0;
		retransmission_delay = T1_expiry - cur_time;
		sendpacket_flag = 0; /* just set the timer, that's all */
		state = S_BOUND;
		return 1;
	} else {
		/* Ignore some superfluous packet. */
		return 0;
	}
}  

int state_bound()
{
	ASSERT_STATE(state, S_BOUND);

	if (!recvpacket_flag) {
		/* T1 has expired. */
		make_request(leasepacket, sendpacket);
		sendpacket_flag = 1;
		/* XXX: should really unicast here, but to whom? */
		destination = broadcast_address;
		/* XXX: SHOULD WE DO RETRANSMISSIONS HERE? */
		retransmissions_left = 0;
		retransmission_delay = T2_expiry - cur_time;
		state = S_RENEWING;
		return 1;
	} else {
		/* Ignore some superfluous packet. */
		return 0;
	}
}  

int state_renewing()
{
	ASSERT_STATE(state, S_RENEWING);

	if (!recvpacket_flag) {
		/* T2 has expired. */
		debug("T2 expired");
		sendpacket_flag = 1;
		destination = broadcast_address;
		/* XXX: SHOULD WE DO RETRANSMISSIONS HERE? */
		retransmissions_left = 0;
		retransmission_delay = lease_expiry - cur_time;
		state = S_REBINDING;
		return 1;
	} else if (recvpacket->packet_type == DHCPNAK) {
		warn("lease renewal denied!");
		state = S_INIT;
		return state_init();
	} else if (recvpacket->packet_type == DHCPACK) {
		/* Record new lease info, and set timer to T1. */
		debug("lease renewed");
		deep_packet_copy(leasepacket, recvpacket);
		lease_expiry = abs_time(leasepacket, DHO_DHCP_LEASE_TIME);
		T1_expiry = abs_time(leasepacket, DHO_DHCP_RENEWAL_TIME);
		T2_expiry = abs_time(leasepacket, DHO_DHCP_REBINDING_TIME);
		retransmissions_left = 0;
		retransmission_delay = T1_expiry - cur_time;
		sendpacket_flag = 0; /* just set the timer, that's all */
		state = S_BOUND;
		return 1;
	} else {
		/* Ignore some superfluous packet. */
		return 0;
	}
}  

int state_rebinding()
{
	ASSERT_STATE(state, S_REBINDING);

	if (!recvpacket_flag) {
       		/* Lease has expired! */
		warn("DHCP lease expired!");
		state = S_INIT;
		return state_init();
	} else if (recvpacket->packet_type == DHCPNAK) {
		warn("lease rebinding denied!");
		state = S_INIT;
		return state_init();
	} else if (recvpacket->packet_type == DHCPACK) {
		/* Record new lease info, and set timer to T1. */
		debug("lease rebound");
		deep_packet_copy(leasepacket, recvpacket);
		lease_expiry = abs_time(leasepacket, DHO_DHCP_LEASE_TIME);
		T1_expiry = abs_time(leasepacket, DHO_DHCP_RENEWAL_TIME);
		T2_expiry = abs_time(leasepacket, DHO_DHCP_REBINDING_TIME);
		retransmissions_left = 0;
		retransmission_delay = T1_expiry - cur_time;
		sendpacket_flag = 0; /* just set the timer, that's all */
		state = S_BOUND;
		return 1;
	} else {
		/* Ignore some superfluous packet. */
		return 0;
	}
}  

/* Read the time offset from a given DHCP option and return it as an
 * absolute moment in time (offset from cur_time). */
TIME abs_time(pkt, optnum)
     struct packet *pkt;
     int optnum;
{
	if (pkt == NULL) {
		error ("Bad parameter passed to abs_time");
	}

	return cur_time + 
		(TIME) ntohl(*((u_int32_t *)pkt->options[optnum].data));
}

/* This little number lets you record an interesting packet's contents in
 * another (pre-allocated) packet struct. */
/* XXX: what about haddr? */
void deep_packet_copy(to, from)
     struct packet *to;
     struct packet *from;
{
	struct dhcp_packet *raw;

	if ((to==NULL) || (to->raw==NULL)) {
		error("Bad parameter passed to deep_packet_copy");
	}

	raw = to->raw;
	memcpy (to->raw, from->raw, sizeof *from->raw);
	memcpy (to, from, sizeof *from);
	to->raw = raw;
}


/* Read a DHCP packet from this interface into this (pre-allocated) packet. 
 * If the data on this interface is bogus (non-DHCP), 
 * set pkt->options_valid = 0.
 * Much of this code is stolen from dispatch.c.
 */
void read_packet(interface, pkt) 
     struct interface_info *interface;
     struct packet *pkt;
{
	struct dhcp_packet *dhcp_pkt;
	struct sockaddr_in from;
	struct hardware *hfrom;
	struct hardware fudge_factor; /* XXX */
	struct iaddr ifrom;
	int len;
	static unsigned char packbuf [4095]; /* Packet input buffer.
						Must be as large as largest
						possible MTU. */

	if (pkt==NULL) {
		error("Bad parameter passed to read_packet");
	}
	pkt->haddr = &fudge_factor;
	if ((pkt->haddr==NULL) || (pkt->raw==NULL)) {
		error("Bad parameter passed to read_packet");
	}

	hfrom = pkt->haddr;
	if ((len = receive_packet (interface, packbuf, sizeof packbuf,
				      &from, hfrom)) < 0) {
		warn ("receive_packet failed on %s: %m", interface -> name);
		pkt->options_valid = 0;
		return;
	}
	if (len == 0) {
		pkt->options_valid = 0;
		return;
	}

	ifrom.len = 4;
	memcpy (ifrom.iabuf, &from.sin_addr, ifrom.len);
	
	dhcp_pkt = pkt->raw;
	memcpy (dhcp_pkt, packbuf, len);
	memset (pkt, 0, sizeof (struct packet));
	pkt->raw = dhcp_pkt;
	pkt->packet_length = len;
	pkt->client_port = from.sin_port;
	pkt->client_addr = ifrom;
	pkt->interface = interface;
	pkt->haddr = hfrom;
	
	parse_options (pkt);
	if (pkt->options_valid &&
	    pkt->options [DHO_DHCP_MESSAGE_TYPE].data) {
		pkt->packet_type =
			pkt->options [DHO_DHCP_MESSAGE_TYPE].data [0];
	} else {
		pkt->options_valid = 0;
	}
	pkt->haddr = NULL; /* XXX */

#ifdef DEBUG
	dump_packet(pkt);
#endif
}

int commit_leases ()
{
	return 0;
}

int write_lease (lease)
	struct lease *lease;
{
	return 0;
}

void db_startup ()
{
}

void bootp (packet)
	struct packet *packet;
{
	note ("BOOTREPLY from %s",
	      print_hw_addr (packet -> raw -> htype,
			     packet -> raw -> hlen,
			     packet -> raw -> chaddr));
}

void dhcp (packet)
	struct packet *packet;
{
	switch (packet -> packet_type) {
	      case DHCPOFFER:
		dhcpoffer (packet);
		break;

	      case DHCPNAK:
		dhcpnak (packet);
		break;

	      case DHCPACK:
		dhcpack (packet);
		break;

	      default:
		break;
	}
}

void dhcpoffer (packet)
	struct packet *packet;
{
	note ("DHCPOFFER from %s",
	      print_hw_addr (packet -> raw -> htype,
			     packet -> raw -> hlen,
			     packet -> raw -> chaddr));

	dump_packet (packet);
	note ("DHCPREQUEST to %s", packet -> interface -> name);
	send_request (packet);
}

void dhcpack (packet)
	struct packet *packet;
{
	note ("DHCPACK from %s",
	      print_hw_addr (packet -> raw -> htype,
			     packet -> raw -> hlen,
			     packet -> raw -> chaddr));
	dump_packet (packet);
}

void dhcpnak (packet)
	struct packet *packet;
{
	note ("DHCPNAK from %s",
	      print_hw_addr (packet -> raw -> htype,
			     packet -> raw -> hlen,
			     packet -> raw -> chaddr));
}

void send_discover (interface)
	struct interface_info *interface;
{
	struct packet outgoing;
	struct dhcp_packet raw;

	outgoing.raw = &raw;
	make_discover (interface, &outgoing);
	send_packet_struct (interface, htonl(INADDR_BROADCAST), &outgoing);
}

void send_request (packet)
	struct packet *packet; /* incoming packet we're responding to */
{
	struct packet outgoing;
	struct dhcp_packet raw;

	outgoing.raw = &raw;
	make_request (packet, &outgoing);
	send_packet_struct (packet->interface, htonl(INADDR_BROADCAST), 
			    &outgoing);
}

void send_release (packet)
	struct packet *packet; /* DHCPACK packet from lease we're releasing */
{
	struct packet outgoing;
	struct dhcp_packet raw;

	outgoing.raw = &raw;
	make_release (packet, &outgoing);
	send_packet_struct (packet->interface, htonl(INADDR_BROADCAST), 
			    &outgoing);
}

/* Send the given packet to the given host IPaddr, over the given interface. */
void send_packet_struct (interface, dest_host, sendpkt)
	struct interface_info *interface;
	u_long dest_host;  /* in network order! */
	struct packet *sendpkt;
{
	struct sockaddr_in to;
	int result;
	char dhcpbuf [128];

	/* Set up the common stuff... */
	to.sin_family = AF_INET;
#ifdef HAVE_SA_LEN
	to.sin_len = sizeof to;
#endif
	memset (to.sin_zero, 0, sizeof to.sin_zero);

	to.sin_addr.s_addr = dest_host;
	to.sin_port = htons (ntohs (server_port) - 1); /* XXX */

	sprintf (dhcpbuf, "DHCP Unknown %d", sendpkt -> packet_type);
	note ("%s to %s",
	      sendpkt -> packet_type == DHCPDISCOVER ? "DHCPDISCOVER"
	      : (sendpkt -> packet_type == DHCPREQUEST ? "DHCPREQUEST"
		 : (sendpkt -> packet_type == DHCPNAK ? "DHCPNAK"
		    : (sendpkt -> packet_type == DHCPINFORM ? "DHCPINFORM"
		       : dhcpbuf))),
	      inet_ntoa (to.sin_addr));
	      
	if (sendpkt->packet_length < DHCP_MIN_LEN)
		sendpkt->packet_length = DHCP_MIN_LEN;

	errno = 0;
	result = send_packet (interface, (struct packet *)0,
			      sendpkt->raw, sendpkt->packet_length,
			      sendpkt->raw->siaddr, &to, (struct hardware *)0);
	/* XXX: is the above 'siaddr' correct? */
	if (result < 0)
		warn ("send_packet: %m");
}

void make_discover (interface, sendpkt)
	struct interface_info *interface;
	struct packet *sendpkt;
{
	struct dhcp_packet *raw;
	unsigned char discover = DHCPDISCOVER;

	struct tree_cache *options [256];
	struct tree_cache dhcpdiscover_tree;
	struct tree_cache dhcprqo_tree;

	u_int8_t requested_options [] = {
		DHO_SUBNET_MASK,
		DHO_ROUTERS,
		DHO_DOMAIN_NAME_SERVERS,
		DHO_HOST_NAME,
		DHO_DOMAIN_NAME,
		DHO_BROADCAST_ADDRESS };

	raw = sendpkt->raw;
	memset (options, 0, sizeof options);
	memset (sendpkt, 0, sizeof (*sendpkt));
	memset (raw, 0, sizeof (*raw));
	sendpkt->raw = raw;
	sendpkt -> packet_type = DHCPDISCOVER;

	/* Set DHCP_MESSAGE_TYPE to DHCPDISCOVER */
	options [DHO_DHCP_MESSAGE_TYPE] = &dhcpdiscover_tree;
	options [DHO_DHCP_MESSAGE_TYPE] -> value = &discover;
	options [DHO_DHCP_MESSAGE_TYPE] -> len = sizeof discover;
	options [DHO_DHCP_MESSAGE_TYPE] -> buf_size = sizeof discover;
	options [DHO_DHCP_MESSAGE_TYPE] -> timeout = 0xFFFFFFFF;
	options [DHO_DHCP_MESSAGE_TYPE] -> tree = (struct tree *)0;

	/* Request the parameters we want */
	options [DHO_DHCP_PARAMETER_REQUEST_LIST] = &dhcprqo_tree;
	options [DHO_DHCP_PARAMETER_REQUEST_LIST] -> value = requested_options;
	options [DHO_DHCP_PARAMETER_REQUEST_LIST] -> len = sizeof requested_options;
	options [DHO_DHCP_PARAMETER_REQUEST_LIST] -> buf_size = sizeof requested_options;
	options [DHO_DHCP_PARAMETER_REQUEST_LIST] -> timeout = 0xFFFFFFFF;
	options [DHO_DHCP_PARAMETER_REQUEST_LIST] -> tree = (struct tree *)0;

	/* Set up the option buffer... */
	cons_options ((struct packet *)0, sendpkt, options, 0, 0);

	raw->op = BOOTREQUEST;
	raw->htype = interface -> hw_address.htype;
	raw->hlen = interface -> hw_address.hlen;
	raw->hops = 0;
	raw->xid = random ();
	raw->secs = 0; /* XXX */
	raw->flags = htons (BOOTP_BROADCAST);
	memset (&(raw->ciaddr), 0, sizeof raw->ciaddr);
	memset (&(raw->yiaddr), 0, sizeof raw->yiaddr);
	memset (&(raw->siaddr), 0, sizeof raw->siaddr);
	memset (&(raw->giaddr), 0, sizeof raw->giaddr);
	memcpy (raw->chaddr,
		interface -> hw_address.haddr, interface -> hw_address.hlen);

#ifdef DEBUG_PACKET
	dump_packet (sendpkt);
	dump_raw ((unsigned char *)raw, sendpkt->packet_length);
#endif
}


void make_request (recvpkt, sendpkt)
     struct packet *recvpkt;
     struct packet *sendpkt;
{
	struct dhcp_packet *raw;
	unsigned char request = DHCPREQUEST;

	struct tree_cache *options [256];
	struct tree_cache dhcprequest_tree;
	struct tree_cache dhcprqo_tree;
	struct tree_cache dhcprqa_tree;
	struct tree_cache dhcpsid_tree;

	u_int8_t requested_options [] = {
		DHO_SUBNET_MASK,
		DHO_ROUTERS,
		DHO_DOMAIN_NAME_SERVERS,
		DHO_HOST_NAME,
		DHO_DOMAIN_NAME,
		DHO_BROADCAST_ADDRESS };

	raw = sendpkt->raw;
	memset (options, 0, sizeof options);
	memset (sendpkt, 0, sizeof (*sendpkt));
	memset (raw, 0, sizeof (*raw));
	sendpkt->raw = raw;

	sendpkt -> packet_type = DHCPREQUEST;

	/* Set DHCP_MESSAGE_TYPE to DHCPREQUEST */
	options [DHO_DHCP_MESSAGE_TYPE] = &dhcprequest_tree;
	options [DHO_DHCP_MESSAGE_TYPE] -> value = &request;
	options [DHO_DHCP_MESSAGE_TYPE] -> len = sizeof request;
	options [DHO_DHCP_MESSAGE_TYPE] -> buf_size = sizeof request;
	options [DHO_DHCP_MESSAGE_TYPE] -> timeout = 0xFFFFFFFF;
	options [DHO_DHCP_MESSAGE_TYPE] -> tree = (struct tree *)0;

	/* Request the parameters we want */
	options [DHO_DHCP_PARAMETER_REQUEST_LIST] = &dhcprqo_tree;
	options [DHO_DHCP_PARAMETER_REQUEST_LIST] -> value = requested_options;
	options [DHO_DHCP_PARAMETER_REQUEST_LIST] -> len = sizeof requested_options;
	options [DHO_DHCP_PARAMETER_REQUEST_LIST] -> buf_size = sizeof requested_options;
	options [DHO_DHCP_PARAMETER_REQUEST_LIST] -> timeout = 0xFFFFFFFF;
	options [DHO_DHCP_PARAMETER_REQUEST_LIST] -> tree = (struct tree *)0;

	/* Send back the server identifier... */
        options [DHO_DHCP_SERVER_IDENTIFIER] = &dhcpsid_tree;
        options [DHO_DHCP_SERVER_IDENTIFIER] -> value =
                recvpkt -> options [DHO_DHCP_SERVER_IDENTIFIER].data;
        options [DHO_DHCP_SERVER_IDENTIFIER] -> len =
                recvpkt -> options [DHO_DHCP_SERVER_IDENTIFIER].len;
        options [DHO_DHCP_SERVER_IDENTIFIER] -> buf_size =
                recvpkt -> options [DHO_DHCP_SERVER_IDENTIFIER].len;
        options [DHO_DHCP_SERVER_IDENTIFIER] -> timeout = 0xFFFFFFFF;
        options [DHO_DHCP_SERVER_IDENTIFIER] -> tree = (struct tree *)0;

	/* Set up the option buffer... */
	cons_options ((struct packet *)0, sendpkt, options, 0, 0);

	raw->op = BOOTREQUEST;
	raw->htype = recvpkt -> interface -> hw_address.htype;
	raw->hlen = recvpkt -> interface -> hw_address.hlen;
	raw->hops = 0;
	raw->xid = recvpkt -> raw -> xid;
	raw->secs = recvpkt -> raw -> secs; /* XXX */
	raw->flags = htons (BOOTP_BROADCAST);
	raw->ciaddr = recvpkt -> raw -> yiaddr; /* XXX ????? */
	memset (&raw->yiaddr, 0, sizeof raw->yiaddr);
	memset (&raw->siaddr, 0, sizeof raw->siaddr);
	memset (&raw->giaddr, 0, sizeof raw->giaddr);
	memcpy (raw->chaddr,
		recvpkt -> interface -> hw_address.haddr,
		recvpkt -> interface -> hw_address.hlen);

#ifdef DEBUG_PACKET
	dump_packet (sendpkt);
	dump_raw ((unsigned char *)raw, sendpkt->packet_length);
#endif
}

void make_release (recvpkt, sendpkt)
     struct packet *recvpkt;
     struct packet *sendpkt;
{
	struct dhcp_packet *raw;
	unsigned char request = DHCPRELEASE;

	struct tree_cache *options [256];
	struct tree_cache dhcprequest_tree;
	struct tree_cache dhcprqo_tree;
	struct tree_cache dhcprqa_tree;
	struct tree_cache dhcpsid_tree;

	raw = sendpkt->raw;
	memset (options, 0, sizeof options);
	memset (sendpkt, 0, sizeof (*sendpkt));
	memset (raw, 0, sizeof (*raw));
	sendpkt->raw = raw;

	sendpkt -> packet_type = DHCPRELEASE;

	/* Set DHCP_MESSAGE_TYPE to DHCPRELEASE */
	options [DHO_DHCP_MESSAGE_TYPE] = &dhcprequest_tree;
	options [DHO_DHCP_MESSAGE_TYPE] -> value = &request;
	options [DHO_DHCP_MESSAGE_TYPE] -> len = sizeof request;
	options [DHO_DHCP_MESSAGE_TYPE] -> buf_size = sizeof request;
	options [DHO_DHCP_MESSAGE_TYPE] -> timeout = 0xFFFFFFFF;
	options [DHO_DHCP_MESSAGE_TYPE] -> tree = (struct tree *)0;

	/* Send back the server identifier... */
        options [DHO_DHCP_SERVER_IDENTIFIER] = &dhcpsid_tree;
        options [DHO_DHCP_SERVER_IDENTIFIER] -> value =
                recvpkt -> options [DHO_DHCP_SERVER_IDENTIFIER].data;
        options [DHO_DHCP_SERVER_IDENTIFIER] -> len =
                recvpkt -> options [DHO_DHCP_SERVER_IDENTIFIER].len;
        options [DHO_DHCP_SERVER_IDENTIFIER] -> buf_size =
                recvpkt -> options [DHO_DHCP_SERVER_IDENTIFIER].len;
        options [DHO_DHCP_SERVER_IDENTIFIER] -> timeout = 0xFFFFFFFF;
        options [DHO_DHCP_SERVER_IDENTIFIER] -> tree = (struct tree *)0;

	/* Set DHCP_MESSAGE to whatever the message is */
	/* XXX */

	/* Set up the option buffer... */
	cons_options ((struct packet *)0, sendpkt, options, 0, 0);

	raw->op = BOOTREQUEST;
	raw->htype = recvpkt -> interface -> hw_address.htype;
	raw->hlen = recvpkt -> interface -> hw_address.hlen;
	raw->hops = 0;
	raw->xid = recvpkt -> raw -> xid;
	raw->secs = 0;
	raw->flags = 0;
	raw->ciaddr = recvpkt -> raw -> yiaddr;
	memset (&raw->yiaddr, 0, sizeof raw->yiaddr);
	memset (&raw->siaddr, 0, sizeof raw->siaddr);
	memset (&raw->giaddr, 0, sizeof raw->giaddr);
	memcpy (raw->chaddr,
		recvpkt -> interface -> hw_address.haddr,
		recvpkt -> interface -> hw_address.hlen);


#ifdef DEBUG_PACKET
	dump_packet (sendpkt);
	dump_raw ((unsigned char *)raw, sendpkt->packet_length);
#endif
}
