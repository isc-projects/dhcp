/* dhcpdi.c

   Text interaction routines for dhcp server. */

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
"$Id: dhcpdi.c,v 1.1 1998/04/09 05:19:26 mellon Exp $ Copyright (c) 1998 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

static void top_level_ls PROTO ((struct interact_client *));
static void top_level_print PROTO ((struct interact_client *, char *));
static void top_level_set PROTO ((struct interact_client *, char *));
static void top_level_rm PROTO ((struct interact_client *, char *));
static void top_level_cd PROTO ((struct interact_client *, char *));
static void top_level_cdup PROTO ((struct interact_client *));
static void *top_level_next PROTO ((struct interact_client *, void *));

static void interface_class_ls PROTO ((struct interact_client *));
static void interface_class_print PROTO ((struct interact_client *, char *));
static void interface_class_set PROTO ((struct interact_client *, char *));
static void interface_class_rm PROTO ((struct interact_client *, char *));
static void interface_class_cd PROTO ((struct interact_client *, char *));
static void interface_class_cdup PROTO ((struct interact_client *));
static void *interface_class_next PROTO ((struct interact_client *, void *));

static void interface_ls PROTO ((struct interact_client *));
static void interface_print PROTO ((struct interact_client *, char *));
static void interface_set PROTO ((struct interact_client *, char *));
static void interface_rm PROTO ((struct interact_client *, char *));
static void interface_cd PROTO ((struct interact_client *, char *));
static void interface_cdup PROTO ((struct interact_client *));
static void *interface_next PROTO ((struct interact_client *, void *));

static void shared_network_ls PROTO ((struct interact_client *));
static void shared_network_class_ls PROTO ((struct interact_client *));
static void shared_network_class_print PROTO ((struct interact_client *,
					       char *));
static void shared_network_class_set PROTO ((struct interact_client *,
					     char *));
static void shared_network_class_rm PROTO ((struct interact_client *,
					    char *));
static void shared_network_class_cd PROTO ((struct interact_client *,
					    char *));
static void shared_network_class_cdup PROTO ((struct interact_client *));
static void *shared_network_class_next PROTO ((struct interact_client *,
					       void *));

static void shared_network_print PROTO ((struct interact_client *, char *));
static void shared_network_set PROTO ((struct interact_client *, char *));
static void shared_network_rm PROTO ((struct interact_client *, char *));
static void shared_network_cd PROTO ((struct interact_client *, char *));
static void shared_network_cdup PROTO ((struct interact_client *));
static void *shared_network_next PROTO ((struct interact_client *, void *));

static void subnet_class_ls PROTO ((struct interact_client *));
static void subnet_class_print PROTO ((struct interact_client *, char *));
static void subnet_class_set PROTO ((struct interact_client *, char *));
static void subnet_class_rm PROTO ((struct interact_client *, char *));
static void subnet_class_cd PROTO ((struct interact_client *, char *));
static void subnet_class_cdup PROTO ((struct interact_client *));
static void *subnet_class_next PROTO ((struct interact_client *, void *));
static void *subnet_class_next_share PROTO ((struct interact_client *,
					     void *));

static void subnet_ls PROTO ((struct interact_client *));
static void subnet_print PROTO ((struct interact_client *, char *));
static void subnet_set PROTO ((struct interact_client *, char *));
static void subnet_rm PROTO ((struct interact_client *, char *));
static void subnet_cd PROTO ((struct interact_client *, char *));
static void subnet_cdup PROTO ((struct interact_client *));
static void *subnet_next PROTO ((struct interact_client *, void *));

static void host_class_ls PROTO ((struct interact_client *));
static void host_class_print PROTO ((struct interact_client *, char *));
static void host_class_set PROTO ((struct interact_client *, char *));
static void host_class_rm PROTO ((struct interact_client *, char *));
static void host_class_cd PROTO ((struct interact_client *, char *));
static void host_class_cdup PROTO ((struct interact_client *));
static void *host_class_next PROTO ((struct interact_client *, void *));

static void host_ls PROTO ((struct interact_client *));
static void host_print PROTO ((struct interact_client *, char *));
static void host_set PROTO ((struct interact_client *, char *));
static void host_rm PROTO ((struct interact_client *, char *));
static void host_cd PROTO ((struct interact_client *, char *));
static void host_cdup PROTO ((struct interact_client *));
static void *host_next PROTO ((struct interact_client *, void *));

static void lease_ls PROTO ((struct interact_client *));
static void lease_print PROTO ((struct interact_client *, char *));
static void lease_set PROTO ((struct interact_client *, char *));
static void lease_rm PROTO ((struct interact_client *, char *));
static void lease_cd PROTO ((struct interact_client *, char *));
static void lease_cdup PROTO ((struct interact_client *));
static void lease_cdup_host PROTO ((struct interact_client *));
static void *lease_next PROTO ((struct interact_client *, void *));

static void *lease_next_active PROTO ((struct interact_client *, void *));
static void *lease_next_free PROTO ((struct interact_client *, void *));
static void *lease_next_abandoned PROTO ((struct interact_client *, void *));

static void class_class_ls PROTO ((struct interact_client *));
static void class_class_print PROTO ((struct interact_client *, char *));
static void class_class_set PROTO ((struct interact_client *, char *));
static void class_class_rm PROTO ((struct interact_client *, char *));
static void class_class_cd PROTO ((struct interact_client *, char *));
static void class_class_cdup PROTO ((struct interact_client *));
static void *class_class_next PROTO ((struct interact_client *, void *));

static void class_ls PROTO ((struct interact_client *));
static void class_print PROTO ((struct interact_client *, char *));
static void class_set PROTO ((struct interact_client *, char *));
static void class_rm PROTO ((struct interact_client *, char *));
static void class_cd PROTO ((struct interact_client *, char *));
static void class_cdup PROTO ((struct interact_client *));
static void *class_next PROTO ((struct interact_client *, void *));

static void group_ls PROTO ((struct interact_client *));
static void group_print PROTO ((struct interact_client *, char *));
static void group_set PROTO ((struct interact_client *, char *));
static void group_rm PROTO ((struct interact_client *, char *));
static void group_cd PROTO ((struct interact_client *, char *));
static void group_cdup PROTO ((struct interact_client *));
static void group_cdup_share PROTO ((struct interact_client *));
static void *group_next PROTO ((struct interact_client *, void *));

struct interact_actions top_level_actions = {
	top_level_ls,
	top_level_print,
	top_level_set,
	top_level_rm,
	top_level_cd,
	top_level_cdup,
	top_level_next };

static struct interact_actions interface_class_actions = {
	interface_class_ls,
	interface_class_print,
	interface_class_set,
	interface_class_rm,
	interface_class_cd,
	interface_class_cdup,
	interface_class_next };

static struct interact_actions interface_actions = {
	interface_ls,
	interface_print,
	interface_set,
	interface_rm,
	interface_cd,
	interface_cdup,
	interface_next };

static struct interact_actions shared_network_class_actions = {
	shared_network_class_ls,
	shared_network_class_print,
	shared_network_class_set,
	shared_network_class_rm,
	shared_network_class_cd,
	shared_network_class_cdup,
	shared_network_class_next };

static struct interact_actions shared_network_actions = {
	shared_network_ls,
	shared_network_print,
	shared_network_set,
	shared_network_rm,
	shared_network_cd,
	shared_network_cdup,
	shared_network_next };

static struct interact_actions subnet_class_actions = {
	subnet_class_ls,
	subnet_class_print,
	subnet_class_set,
	subnet_class_rm,
	subnet_class_cd,
	subnet_class_cdup,
	subnet_class_next };

static struct interact_actions subnet_actions = {
	subnet_ls,
	subnet_print,
	subnet_set,
	subnet_rm,
	subnet_cd,
	subnet_cdup,
	subnet_next };

static struct interact_actions host_class_actions = {
	host_class_ls,
	host_class_print,
	host_class_set,
	host_class_rm,
	host_class_cd,
	host_class_cdup,
	host_class_next };

static struct interact_actions host_actions = {
	host_ls,
	host_print,
	host_set,
	host_rm,
	host_cd,
	host_cdup,
	host_next };

static struct interact_actions lease_actions = {
	lease_ls,
	lease_print,
	lease_set,
	lease_rm,
	lease_cd,
	lease_cdup,
	lease_next };

static struct interact_actions class_class_actions = {
	class_class_ls,
	class_class_print,
	class_class_set,
	class_class_rm,
	class_class_cd,
	class_class_cdup,
	class_class_next };

static struct interact_actions class_actions = {
	class_ls,
	class_print,
	class_set,
	class_rm,
	class_cd,
	class_cdup,
	class_next };

static struct interact_actions group_actions = {
	group_ls,
	group_print,
	group_set,
	group_rm,
	group_cd,
	group_cdup,
	group_next };


static void top_level_ls (client)
	struct interact_client *client;
{
	interact_client_write (client, "interfaces", 0);
	interact_client_write (client, "shared networks", 0);
	interact_client_write (client, "subnets", 0);
	interact_client_write (client, "classes", 0);
	interact_client_write (client, "hosts", 1);
}

static void top_level_print (client, string)
	struct interact_client *client;
	char *string;
{
	interact_client_write (client, "can't print that.", 1);
}

static void top_level_set (client, string)
	struct interact_client *client;
	char *string;
{
	interact_client_write (client, "can't set that.", 1);
}

static void top_level_rm (client, string)
	struct interact_client *client;
	char *string;
{
	interact_client_write (client, "can't remove that.", 1);
}

static void top_level_cd (client, string)
	struct interact_client *client;
	char *string;
{
	if (!strcmp (string, "interfaces")) {
		client -> cur_node_actions = interface_actions;
		client -> cur_node_actions.cdup = top_level_cdup;
	} else if (!strcmp (string, "shared networks")) {
		client -> cur_node_actions = shared_network_actions;
		client -> cur_node_actions.cdup = top_level_cdup;
	} else if (!strcmp (string, "subnets")) {
		client -> cur_node_actions = subnet_actions;
		client -> cur_node_actions.cdup = top_level_cdup;
	} else if (!strcmp (string, "classes")) {
		client -> cur_node_actions = class_actions;
		client -> cur_node_actions.cdup = top_level_cdup;
	} else if (!strcmp (string, "hosts")) {
		client -> cur_node_actions = host_actions;
		client -> cur_node_actions.cdup = top_level_cdup;
	} else {
		interact_client_write (client, "can't cd to that.", 1);
		return;
	}
	interact_client_write (client, "done.", 1);
}

static void top_level_cdup (client)
	struct interact_client *client;
{
	client -> cur_node_actions = top_level_actions;
	client -> cur_node = (void *)0;
}

static void *top_level_next (client, ptr)
	struct interact_client *client;
	void *ptr;
{
	return (void *)0;
}

static void interface_class_ls (client)
	struct interact_client *client;
{
	struct interface_info *ip = client -> cur_node;

	for (ip = interfaces; ip; ip = ip -> next) {
		interact_client_write (client, ip -> name, ip -> next ? 0 : 1);
	}
}

static void interface_class_print (client, string)
	struct interact_client *client;
	char *string;
{
	interact_client_write (client, "nothing to print.", 1);
}

static void interface_class_set (client, string)
	struct interact_client *client;
	char *string;
{
	interact_client_write (client, "can't set that.", 1);
}

static void interface_class_rm (client, string)
	struct interact_client *client;
	char *string;
{
	interact_client_write (client, "can't remove that.", 1);
}

static void interface_class_cd (client, string)
	struct interact_client *client;
	char *string;
{
	int i;
	struct interface_info *ip;

	i = strlen (string);
	for (ip = interfaces; ip; ip = ip -> next)
		if (!strcmp (ip -> name, string))
			break;
	if (!ip) {
		interact_client_write (client, "no such interface.", 1);
		return;
	}
	client -> cur_node = ip;
	client -> cur_node_actions = interface_class_actions;
	interact_client_write (client, "done.", 1);
}

static void interface_class_cdup (client)
	struct interact_client *client;
{
	struct interface_info *ip = client -> cur_node;
	
	client -> cur_node = ip -> shared_network;
	client -> cur_node_actions = shared_network_actions;
	client -> cur_node_actions.cdup = top_level_cdup;
}

static void *interface_class_next (client, ptr)
	struct interact_client *client;
	void *ptr;
{
	return (void *)0;
}

static void interface_ls (client)
	struct interact_client *client;
{
	struct interface_info *ip = client -> cur_node;

	if (ip -> shared_network)
		interact_client_write (client, "shared network", 0);
	if (ip -> primary_address.s_addr)
		interact_client_write (client, "ip address", 0);
	if (ip -> client)
		interact_client_write (client, "client state", 0);
	interact_client_write (client, "hardware type", 0);
	interact_client_write (client, "hardware address", 1);
}

static void interface_print (client, string)
	struct interact_client *client;
	char *string;
{
	struct interface_info *ip = client -> cur_node;

	if (!strcmp (string, "ip address"))
		interact_client_write (client,
				       inet_ntoa (ip -> primary_address), 1);
	else if (!strcmp (string, "hardware type"))
		interact_client_write (client,
				       hardware_types [ip -> hw_address.htype],
				       1);
	else if (!strcmp (string, "hardware address"))
		interact_client_write (client,
				       print_hw_addr (ip -> hw_address.htype,
						      ip -> hw_address.hlen,
						      ip -> hw_address.haddr),
				       1);
	else if (!strcmp (string, "shared network"))
		interact_client_write (client,
				       ip -> shared_network -> name, 1);
	else
		interact_client_write (client, "can't print that.", 1);
}

static void interface_set (client, string)
	struct interact_client *client;
	char *string;
{
	interact_client_write (client, "can't set that.", 1);
}

static void interface_rm (client, string)
	struct interact_client *client;
	char *string;
{
	interact_client_write (client, "can't remove that.", 1);
}

static void interface_cd (client, string)
	struct interact_client *client;
	char *string;
{
	struct interface_info *ip = client -> cur_node;
	int i;

	if (!strcmp (string, "shared network")) {
		client -> cur_node_actions = shared_network_actions;
		client -> cur_node_actions.cdup =
			shared_network_cdup;
		client -> cur_node = ip -> shared_network;
		interact_client_write (client, "done.", 1);
	} else
		interact_client_write (client, "can't cd to that.", 1);
}

static void interface_cdup (client)
	struct interact_client *client;
{
	struct interface_info *ip = client -> cur_node;
	
	client -> cur_node = (void *)0;
	client -> cur_node_actions = interface_class_actions;
	client -> cur_node_actions.cdup = top_level_cdup;
}

static void *interface_next (client, ptr)
	struct interact_client *client;
	void *ptr;
{
	return (void *)0;
}

static void shared_network_class_ls (client)
	struct interact_client *client;
{
	interact_client_write (client, "name", 0);
	interact_client_write (client, "subnets", 0);
	interact_client_write (client, "group", 0);
	interact_client_write (client, "leases", 0);
	interact_client_write (client, "active leases", 0);
	interact_client_write (client, "free leases", 0);
	interact_client_write (client, "abandoned leases", 1);
}

static void shared_network_class_print (client, string)
	struct interact_client *client;
	char *string;
{
	interact_client_write (client, "nothing to print.", 1);
}

static void shared_network_class_set (client, string)
	struct interact_client *client;
	char *string;
{
	interact_client_write (client, "can't set that.", 1);
}

static void shared_network_class_rm (client, string)
	struct interact_client *client;
	char *string;
{
	interact_client_write (client, "can't remove that.", 1);
}

static void shared_network_class_cd (client, string)
	struct interact_client *client;
	char *string;
{
	struct shared_network *share = client -> cur_node;

	if (!strcmp (string, "subnets")) {
		client -> cur_node = share -> subnets;
		client -> cur_node_actions = subnet_class_actions;
		client -> cur_node_actions.next = subnet_class_next_share;
		client -> cur_node_actions.cdup = subnet_class_cdup;
	} else if (!strcmp (string, "group")) {
		client -> cur_node = share -> group;
		client -> cur_node_actions = group_actions;
		client -> cur_node_actions.cdup = group_cdup_share;
	} else if (!strcmp (string, "leases")) {
		client -> cur_node = share -> leases;
		client -> cur_node_actions = lease_actions;
	} else if (!strcmp (string, "active leases")) {
		client -> cur_node = share -> leases;
		client -> cur_node_actions = lease_actions;
		client -> cur_node_actions.next = lease_next_active;
	} else if (!strcmp (string, "free leases")) {
		client -> cur_node = share -> leases;
		client -> cur_node_actions = lease_actions;
		client -> cur_node_actions.next = lease_next_free;
	} else if (!strcmp (string, "abandoned leases")) {
		client -> cur_node = share -> leases;
		client -> cur_node_actions = lease_actions;
		client -> cur_node_actions.next = lease_next_abandoned;
	} else {
		interact_client_write (client, "can't cd to that.", 1);
		return;
	}
	interact_client_write (client, "done.", 1);
}

static void shared_network_class_cdup (client)
	struct interact_client *client;
{
	struct shared_network *share = client -> cur_node;

	if (share -> interface)
		client -> cur_node = share -> interface;
	else
		top_level_cdup (client);
}

static void *shared_network_class_next (client, ptr)
	struct interact_client *client;
	void *ptr;
{
	return (void *)0;
}

static void shared_network_ls (client)
	struct interact_client *client;
{
}

static void shared_network_print (client, string)
	struct interact_client *client;
	char *string;
{
	interact_client_write (client, "name", 0);
	interact_client_write (client, "subnets", 0);
	interact_client_write (client, "group", 0);
	interact_client_write (client, "leases", 0);
	interact_client_write (client, "active leases", 0);
	interact_client_write (client, "free leases", 0);
	interact_client_write (client, "abandoned leases", 1);
}

static void shared_network_set (client, string)
	struct interact_client *client;
	char *string;
{
	interact_client_write (client, "can't set that.", 1);
}

static void shared_network_rm (client, string)
	struct interact_client *client;
	char *string;
{
	interact_client_write (client, "can't remove that.", 1);
}

static void shared_network_cd (client, string)
	struct interact_client *client;
	char *string;
{
	struct shared_network *share = client -> cur_node;

	if (!strcmp (string, "subnets")) {
		client -> cur_node = share -> subnets;
		client -> cur_node_actions = subnet_actions;
		client -> cur_node_actions.next = subnet_class_next_share;
	} else if (!strcmp (string, "group")) {
		client -> cur_node = share -> group;
		client -> cur_node_actions = group_actions;
		client -> cur_node_actions.cdup = group_cdup_share;
	} else if (!strcmp (string, "leases")) {
		client -> cur_node = share -> leases;
		client -> cur_node_actions = lease_actions;
	} else if (!strcmp (string, "active leases")) {
		client -> cur_node = share -> leases;
		client -> cur_node_actions = lease_actions;
		client -> cur_node_actions.next = lease_next_active;
	} else if (!strcmp (string, "free leases")) {
		client -> cur_node = share -> leases;
		client -> cur_node_actions = lease_actions;
		client -> cur_node_actions.next = lease_next_free;
	} else if (!strcmp (string, "abandoned leases")) {
		client -> cur_node = share -> leases;
		client -> cur_node_actions = lease_actions;
		client -> cur_node_actions.next = lease_next_abandoned;
	} else {
		interact_client_write (client, "can't cd to that.", 1);
		return;
	}
	interact_client_write (client, "done.", 1);
}

static void shared_network_cdup (client)
	struct interact_client *client;
{
	struct shared_network *share = client -> cur_node;

	if (share -> interface)
		client -> cur_node = share -> interface;
	else
		top_level_cdup (client);
}

static void *shared_network_next (client, ptr)
	struct interact_client *client;
	void *ptr;
{
	return (void *)0;
}

static void subnet_class_ls (client)
	struct interact_client *client;
{
}

static void subnet_class_print (client, string)
	struct interact_client *client;
	char *string;
{
}

static void subnet_class_set (client, string)
	struct interact_client *client;
	char *string;
{
}

static void subnet_class_rm (client, string)
	struct interact_client *client;
	char *string;
{
}

static void subnet_class_cd (client, string)
	struct interact_client *client;
	char *string;
{
}

static void subnet_class_cdup (client)
	struct interact_client *client;
{
}

static void *subnet_class_next (client, ptr)
	struct interact_client *client;
	void *ptr;
{
	struct subnet *subnet = ptr;
	return subnet -> next_subnet;
}

static void *subnet_class_next_share (client, ptr)
	struct interact_client *client;
	void *ptr;
{
	struct subnet *subnet = ptr;
	return subnet -> next_sibling;
}

static void subnet_ls (client)
	struct interact_client *client;
{
}

static void subnet_print (client, string)
	struct interact_client *client;
	char *string;
{
}

static void subnet_set (client, string)
	struct interact_client *client;
	char *string;
{
}

static void subnet_rm (client, string)
	struct interact_client *client;
	char *string;
{
}

static void subnet_cd (client, string)
	struct interact_client *client;
	char *string;
{
}

static void subnet_cdup (client)
	struct interact_client *client;
{
}

static void *subnet_next (client, ptr)
	struct interact_client *client;
	void *ptr;
{
	return (void *)0;
}

static void host_class_ls (client)
	struct interact_client *client;
{
}

static void host_class_print (client, string)
	struct interact_client *client;
	char *string;
{
}

static void host_class_set (client, string)
	struct interact_client *client;
	char *string;
{
}

static void host_class_rm (client, string)
	struct interact_client *client;
	char *string;
{
}

static void host_class_cd (client, string)
	struct interact_client *client;
	char *string;
{
}

static void host_class_cdup (client)
	struct interact_client *client;
{
}

static void *host_class_next (client, ptr)
	struct interact_client *client;
	void *ptr;
{
	return (void *)0;
}

static void host_ls (client)
	struct interact_client *client;
{
}

static void host_print (client, string)
	struct interact_client *client;
	char *string;
{
}

static void host_set (client, string)
	struct interact_client *client;
	char *string;
{
}

static void host_rm (client, string)
	struct interact_client *client;
	char *string;
{
}

static void host_cd (client, string)
	struct interact_client *client;
	char *string;
{
}

static void host_cdup (client)
	struct interact_client *client;
{
}

static void *host_next (client, ptr)
	struct interact_client *client;
	void *ptr;
{
	return (void *)0;
}

static void lease_ls (client)
	struct interact_client *client;
{
}

static void lease_print (client, string)
	struct interact_client *client;
	char *string;
{
}

static void lease_set (client, string)
	struct interact_client *client;
	char *string;
{
}

static void lease_rm (client, string)
	struct interact_client *client;
	char *string;
{
}

static void lease_cd (client, string)
	struct interact_client *client;
	char *string;
{
}

static void lease_cdup (client)
	struct interact_client *client;
{
	struct lease *lease = client -> cur_node;
	client -> cur_node = lease -> shared_network;
	client -> cur_node_actions = shared_network_actions;
}

static void lease_cdup_host (client)
	struct interact_client *client;
{
	struct lease *lease = client -> cur_node;
	if (lease -> host) {
		client -> cur_node = lease -> host;
		client -> cur_node_actions = host_actions;
	} else
		lease_cdup (client);
}

static void *lease_next (client, ptr)
	struct interact_client *client;
	void *ptr;
{
	struct lease *lease = ptr;
	return lease -> next;
}

static void *lease_next_active (client, ptr)
	struct interact_client *client;
	void *ptr;
{
	struct lease *lease = ptr;
	for (; lease; lease = lease -> next)
		if (lease -> ends > cur_time)
			return lease;
	return (void *)0;
}

static void *lease_next_free (client, ptr)
	struct interact_client *client;
	void *ptr;
{
	struct lease *lease = ptr;
	for (; lease; lease = lease -> next)
		if (lease -> ends < cur_time)
			return lease;
	return (void *)0;
}

static void *lease_next_abandoned (client, ptr)
	struct interact_client *client;
	void *ptr;
{
	struct lease *lease = ptr;
	for (; lease; lease = lease -> next)
		if (lease -> flags & ABANDONED_LEASE)
			return lease;
	return (void *)0;
}

static void class_class_ls (client)
	struct interact_client *client;
{
}

static void class_class_print (client, string)
	struct interact_client *client;
	char *string;
{
}

static void class_class_set (client, string)
	struct interact_client *client;
	char *string;
{
}

static void class_class_rm (client, string)
	struct interact_client *client;
	char *string;
{
}

static void class_class_cd (client, string)
	struct interact_client *client;
	char *string;
{
}

static void class_class_cdup (client)
	struct interact_client *client;
{
}

static void *class_class_next (client, ptr)
	struct interact_client *client;
	void *ptr;
{
	return (void *)0;
}

static void class_ls (client)
	struct interact_client *client;
{
}

static void class_print (client, string)
	struct interact_client *client;
	char *string;
{
}

static void class_set (client, string)
	struct interact_client *client;
	char *string;
{
}

static void class_rm (client, string)
	struct interact_client *client;
	char *string;
{
}

static void class_cd (client, string)
	struct interact_client *client;
	char *string;
{
}

static void class_cdup (client)
	struct interact_client *client;
{
}

static void *class_next (client, ptr)
	struct interact_client *client;
	void *ptr;
{
	return (void *)0;
}

static void group_ls (client)
	struct interact_client *client;
{
}

static void group_print (client, string)
	struct interact_client *client;
	char *string;
{
}

static void group_set (client, string)
	struct interact_client *client;
	char *string;
{
}

static void group_rm (client, string)
	struct interact_client *client;
	char *string;
{
}

static void group_cd (client, string)
	struct interact_client *client;
	char *string;
{
}

static void group_cdup (client)
	struct interact_client *client;
{
}

static void group_cdup_share (client)
	struct interact_client *client;
{
}

static void *group_next (client, ptr)
	struct interact_client *client;
	void *ptr;
{
	return (void *)0;
}
