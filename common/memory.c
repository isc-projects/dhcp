/* memory.c

   Memory-resident database... */

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
"@(#) Copyright (c) 1995 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

static struct host_decl *hosts;
static struct hash_table *subnet_hash;
static struct hash_table *lease_uid_hash;
static struct hash_table *lease_ip_addr_hash;
static struct hash_table *lease_hw_addr_hash;
static struct lease *dangling_leases;

void enter_host (hd)
	struct host_decl *hd;
{
	hd -> n_name = hosts;
	hd -> n_haddr = hosts;
	hd -> n_cid = hosts;
	
	hosts = hd;
}

struct host_decl *find_host_by_name (name)
	char *name;
{
	struct host_decl *foo;

	for (foo = hosts; foo; foo = foo -> n_name)
		if (!strcmp (name, foo -> name))
			return foo;
	return (struct host_decl *)0;
}

struct host_decl *find_host_by_addr (htype, haddr, hlen)
	int htype;
	unsigned char *haddr;
	int hlen;
{
	struct host_decl *foo;
	int i;

	for (foo = hosts; foo; foo = foo -> n_haddr)
		for (i = 0; i < foo -> interface_count; i++)
			if (foo -> interfaces [i].htype == htype &&
			    foo -> interfaces [i].hlen == hlen &&
			    !memcmp (foo -> interfaces [i].haddr, haddr, hlen))
				return foo;
	return (struct host_decl *)0;
}

void new_address_range (low, high, netmask)
	struct iaddr low, high, netmask;
{
	struct lease *address_range, *lp, *plp;
	struct subnet *subnet;
	struct iaddr net;
	int i, max;
	char lowbuf [16], highbuf [16], netbuf [16];

	/* Initialize the hash table if it hasn't been done yet. */
	if (!subnet_hash)
		subnet_hash = new_hash ();
	if (!lease_uid_hash)
		lease_uid_hash = new_hash ();
	if (!lease_ip_addr_hash)
		lease_ip_addr_hash = new_hash ();
	if (!lease_hw_addr_hash)
		lease_hw_addr_hash = new_hash ();

	/* Make sure that high and low addresses are in same subnet. */
	net = subnet_number (low, netmask);
	if (!addr_eq (net, subnet_number (high, netmask))) {
		strcpy (lowbuf, piaddr (low));
		strcpy (highbuf, piaddr (high));
		strcpy (netbuf, piaddr (netmask));
		error ("Address range %s to %s, netmask %s spans %s!",
		       lowbuf, highbuf, netbuf, "multiple subnets");
	}

	/* See if this subnet is already known - if not, make a new one. */
	subnet = find_subnet (net);
	if (!subnet) {
		subnet = new_subnet ("new_address_range");
		if (!subnet)
			error ("No memory for new subnet");
		subnet -> net = net;
		subnet -> netmask = netmask;
		subnet -> leases = (struct lease *)0;
		enter_subnet (subnet);
	}

	/* Get the high and low host addresses... */
	max = host_addr (high, netmask);
	i = host_addr (low, netmask);

	/* Allow range to be specified high-to-low as well as low-to-high. */
	if (i > max) {
		max = i;
		i = host_addr (high, netmask);
	}

	/* Get a lease structure for each address in the range. */
	address_range = new_leases (max - i + 1, "new_address_range");
	if (!address_range) {
		strcpy (lowbuf, piaddr (low));
		strcpy (highbuf, piaddr (high));
		error ("No memory for address range %s-%s.", lowbuf, highbuf);
	}
	memset (address_range, 0, (sizeof *address_range) * (max - i + 1));

	/* Fill out the lease structures with some minimal information. */
	for (; i <= max; i++) {
		address_range [i].ip_addr =
			ip_addr (subnet -> net, subnet -> netmask, i);
		address_range [i].starts =
			address_range [i].timestamp = MIN_TIME;
		address_range [i].ends = MIN_TIME;
		address_range [i].contain = subnet;

		/* Link this entry into the list. */
		address_range [i].next = subnet -> leases;
		address_range [i].prev = (struct lease *)0;
		subnet -> leases = &address_range [i];
		if (address_range [i].next)
			address_range [i].next -> prev = subnet -> leases;
		add_hash (lease_ip_addr_hash,
			  (char *)&address_range [i].ip_addr,
			  sizeof address_range [i].ip_addr,
			  (unsigned char *)&address_range [i]);
	}

	/* Find out if any dangling leases are in range... */
	plp = (struct lease *)0;
	for (lp = dangling_leases; lp; lp = lp -> next) {
		struct iaddr lnet;
		int lhost;

		lnet = subnet_number (lp -> ip_addr, subnet -> netmask);
		lhost = host_addr (lp -> ip_addr, subnet -> netmask);

		/* If it's in range, fill in the real lease structure with
		   the dangling lease's values, and remove the lease from
		   the list of dangling leases. */
		if (addr_eq (lnet, subnet -> net) &&
		    lhost >= i && lhost <= max) {
			if (plp) {
				plp -> next = lp -> next;
			} else {
				dangling_leases = lp -> next;
			}
			lp -> next = (struct lease *)0;
			supersede_lease (&address_range [lhost - i], lp);
			free_lease (lp, "new_address_range");
		} else
			plp = lp;
	}
}

struct subnet *find_subnet (subnet)
	struct iaddr subnet;
{
	struct subnet *rv;

	return (struct subnet *)hash_lookup (subnet_hash,
					     (char *)subnet.iabuf, subnet.len);
}

/* Enter a new subnet into the subnet hash. */

void enter_subnet (subnet)
	struct subnet *subnet;
{
	add_hash (subnet_hash, (char *)subnet -> net.iabuf,
		  subnet -> net.len, (unsigned char *)subnet);
}
	
/* Enter a lease into the system.   This is called by the parser each
   time it reads in a new lease.   If the subnet for that lease has
   already been read in (usually the case), just update that lease;
   otherwise, allocate temporary storage for the lease and keep it around
   until we're done reading in the config file. */

void enter_lease (lease)
	struct lease *lease;
{
	struct lease *comp = find_lease_by_ip_addr (lease -> ip_addr);

	/* If we don't have a place for this lease yet, save it for
	   later. */
	if (!comp) {
		comp = new_lease ("enter_lease");
		if (!comp) {
			error ("No memory for lease %s\n",
			       piaddr (lease -> ip_addr));
		}
		*comp = *lease;
		lease -> next = dangling_leases;
		lease -> prev = (struct lease *)0;
		dangling_leases = lease;
	} else {
		supersede_lease (comp, lease);
	}
}

/* Replace the data in an existing lease with the data in a new lease;
   adjust hash tables to suit, and insertion sort the lease into the
   list of leases by expiry time so that we can always find the oldest
   lease. */

void supersede_lease (comp, lease)
	struct lease *comp, *lease;
{
	int enter_uid = 0;
	int enter_hwaddr = 0;
	struct subnet *parent;
	struct lease *lp;

	/* If the existing lease hasn't expired and has a different
	   unique identifier or, if it doesn't have a unique
	   identifier, a different hardware address, then the two
	   leases are in conflict. */
	if (comp -> ends > cur_time &&
	    ((comp -> uid &&
	      (comp -> uid_len != lease -> uid_len ||
	       memcmp (comp -> uid, lease -> uid, comp -> uid_len))) ||
	     (!comp -> uid &&
	      ((comp -> hardware_addr.htype !=
		lease -> hardware_addr.htype) ||
	       (comp -> hardware_addr.hlen !=
		lease -> hardware_addr.hlen) ||
	       memcmp (comp -> hardware_addr.haddr,
		       lease -> hardware_addr.haddr,
		       comp -> hardware_addr.hlen))))) {
		warn ("Lease conflict at %s",
		      piaddr (comp -> ip_addr));
	} else {
		/* If there's a Unique ID, dissociate it from the hash
		   table if necessary, and always free it. */
		if (comp -> uid) {
			if (comp -> uid_len != lease -> uid_len ||
			    memcmp (comp -> uid, lease -> uid,
				    comp -> uid_len)) {
				delete_hash_entry (lease_uid_hash,
						   comp -> uid,
						   comp -> uid_len);
				enter_uid = 1;
			}
			free (comp -> uid);
		}
		if (comp -> hardware_addr.htype &&
		    ((comp -> hardware_addr.hlen !=
		      lease -> hardware_addr.hlen) ||
		     (comp -> hardware_addr.htype !=
		      lease -> hardware_addr.htype) ||
		     memcmp (comp -> hardware_addr.haddr,
			     lease -> hardware_addr.haddr,
			     comp -> hardware_addr.hlen))) {
			delete_hash_entry (lease_hw_addr_hash,
					   comp -> hardware_addr.haddr,
					   comp -> hardware_addr.hlen);
			enter_hwaddr = 1;
		}

		/* Copy the data files, but not the linkages. */
		comp -> starts = lease -> starts;
		comp -> ends = lease -> ends;
		comp -> timestamp = lease -> timestamp;
		comp -> uid = lease -> uid;
		comp -> uid_len = lease -> uid_len;
		comp -> host = lease -> host;
		comp -> hardware_addr = lease -> hardware_addr;
		comp -> state = lease -> state;

		/* Record the lease in the uid hash if necessary. */
		if (enter_uid && lease -> uid) {
			add_hash (lease_uid_hash, lease -> uid,
				  lease -> uid_len, (unsigned char *)lease);
		}

		/* Record it in the hardware address hash if necessary. */
		if (enter_hwaddr && lease -> hardware_addr.htype) {
			add_hash (lease_hw_addr_hash,
				  lease -> hardware_addr.haddr,
				  lease -> hardware_addr.hlen,
				  (unsigned char *)lease);
		}

		/* Remove the lease from its current place in the list. */
		if (comp -> prev) {
			comp -> prev -> next = comp -> next;
		} else {
			comp -> contain -> leases = comp -> next;
		}
		if (comp -> next) {
			comp -> next -> prev = comp -> prev;
		}

		/* Find the last insertion point... */
		if (comp == comp -> contain -> insertion_point ||
		    !comp -> contain -> insertion_point) {
			lp = comp -> contain -> leases;
		} else {
			lp = comp -> contain -> insertion_point;
		}

		if (!lp) {
			/* Nothing on the list yet?    Just make comp the
			   head of the list. */
			comp -> contain -> leases = comp;
		} else if (lp -> ends <= comp -> ends) {
			/* Skip down the list until we run out of list
			   or find a place for comp. */
			while (lp -> next && lp -> ends < comp -> ends) {
				lp = lp -> next;
			}
			if (lp -> ends < comp -> ends) {
				/* If we ran out of list, put comp
				   at the end. */
				lp -> next = comp;
				comp -> prev = lp;
				comp -> next = (struct lease *)0;
			} else {
				/* If we didn't, put it between lp and
				   the previous item on the list. */
				comp -> prev = lp -> prev;
				comp -> prev -> next = comp;
				comp -> next = lp;
				lp -> prev = comp;
			}
		} else {
			/* Skip ip the list until we run out of list
			   or find a place for comp. */
			while (lp -> prev && lp -> ends > comp -> ends) {
				lp = lp -> prev;
			}
			if (lp -> ends > comp -> ends) {
				/* If we ran out of list, put comp
				   at the beginning. */
				lp -> prev = comp;
				comp -> next = lp;
				comp -> prev = (struct lease *)0;
				comp -> contain -> leases = comp;
			} else {
				/* If we didn't, put it between lp and
				   the next item on the list. */
				comp -> next = lp -> next;
				comp -> next -> prev = comp;
				comp -> prev = lp;
				lp -> next = comp;
			}
		}
		comp -> contain -> insertion_point = comp;
	}
}

/* Locate the lease associated with a given IP address... */

struct lease *find_lease_by_ip_addr (addr)
	struct iaddr addr;
{
	struct lease *lease = (struct lease *)hash_lookup (lease_ip_addr_hash,
							   addr.iabuf,
							   addr.len);
	return lease;
}

struct lease *find_lease_by_uid (uid, len)
	unsigned char *uid;
	int len;
{
	struct lease *lease = (struct lease *)hash_lookup (lease_uid_hash,
							   uid, len);
	return lease;
}

