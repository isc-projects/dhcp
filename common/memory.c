/* memory.c

   Memory-resident database... */

/*
 * Copyright (c) 1996-1999 Internet Software Consortium.
 * Use is subject to license terms which appear in the file named
 * ISC-LICENSE that should have accompanied this file when you
 * received it.   If a file named ISC-LICENSE did not accompany this
 * file, or you are not sure the one you have is correct, you may
 * obtain an applicable copy of the license at:
 *
 *             http://www.isc.org/isc-license-1.0.html. 
 *
 * This file is part of the ISC DHCP distribution.   The documentation
 * associated with this file is listed in the file DOCUMENTATION,
 * included in the top-level directory of this release.
 *
 * Support and other services are available for ISC products - see
 * http://www.isc.org for more information.
 */

#ifndef lint
static char copyright[] =
"$Id: memory.c,v 1.52.2.4 1999/10/25 18:33:54 mellon Exp $ Copyright (c) 1995, 1996, 1997, 1998, 1999 The Internet Software Consortium.  All rights reserved.\n";
#endif /* not lint */

#include "dhcpd.h"

static struct subnet *subnets;
static struct shared_network *shared_networks;
static struct hash_table *host_hw_addr_hash;
static struct hash_table *host_uid_hash;
static struct hash_table *lease_uid_hash;
static struct hash_table *lease_ip_addr_hash;
static struct hash_table *lease_hw_addr_hash;
static struct lease *dangling_leases;

void enter_host (hd)
	struct host_decl *hd;
{
	struct host_decl *hp = (struct host_decl *)0;
	struct host_decl *np = (struct host_decl *)0;
	struct executable_statement *esp;

	hd -> n_ipaddr = (struct host_decl *)0;

	if (hd -> interface.hlen) {
		if (!host_hw_addr_hash) {
			host_hw_addr_hash = new_hash ();
			if (!host_hw_addr_hash)
				log_fatal ("Can't allocate host/hw hash");
		} else
			hp = (struct host_decl *)
				hash_lookup (host_hw_addr_hash,
					     hd -> interface.haddr,
					     hd -> interface.hlen);

		/* If there isn't already a host decl matching this
		   address, add it to the hash table. */
		if (!hp)
			add_hash (host_hw_addr_hash,
				  hd -> interface.haddr, hd -> interface.hlen,
				  (unsigned char *)hd);
	}

	/* If there was already a host declaration for this hardware
	   address, add this one to the end of the list. */

	if (hp) {
		for (np = hp; np -> n_ipaddr; np = np -> n_ipaddr)
			;
		np -> n_ipaddr = hd;
	}

	/* See if there's a statement that sets the client identifier.
	   This is a kludge - the client identifier really shouldn't be
	   set with an executable statement. */
	for (esp = hd -> group -> statements; esp; esp = esp -> next) {
		if (esp -> op == supersede_option_statement &&
		    esp -> data.option &&
		    (esp -> data.option -> option -> universe ==
		     &dhcp_universe) &&
		    (esp -> data.option -> option -> code ==
		     DHO_DHCP_CLIENT_IDENTIFIER)) {
			evaluate_option_cache
				(&hd -> client_identifier,
				 (struct packet *)0,
				 (struct option_state *)0,
				 (struct lease *)0,
				 esp -> data.option);
			break;
		}
	}

	/* If we got a client identifier, hash this entry by
	   client identifier. */
	if (hd -> client_identifier.len) {
		/* If there's no uid hash, make one; otherwise, see if
		   there's already an entry in the hash for this host. */
		if (!host_uid_hash) {
			host_uid_hash = new_hash ();
			if (!host_uid_hash)
				log_fatal ("Can't allocate host/uid hash");
			hp = (struct host_decl *)0;
		} else
			hp = ((struct host_decl *)
			      hash_lookup (host_uid_hash,
					   hd -> client_identifier.data,
					   hd -> client_identifier.len));

		/* If there's already a host declaration for this
		   client identifier, add this one to the end of the
		   list.  Otherwise, add it to the hash table. */
		if (hp) {
			/* Don't link it in twice... */
			if (!np) {
				for (np = hp; np -> n_ipaddr;
				     np = np -> n_ipaddr)
					;
				np -> n_ipaddr = hd;
			}
		} else {
			add_hash (host_uid_hash,
				  hd -> client_identifier.data,
				  hd -> client_identifier.len,
				  (unsigned char *)hd);
		}
	}
}

struct host_decl *find_hosts_by_haddr (htype, haddr, hlen)
	int htype;
	unsigned char *haddr;
	int hlen;
{
	struct host_decl *foo;

	foo = (struct host_decl *)hash_lookup (host_hw_addr_hash,
					       haddr, hlen);
	return foo;
}

struct host_decl *find_hosts_by_uid (data, len)
	unsigned char *data;
	int len;
{
	struct host_decl *foo;

	foo = (struct host_decl *)hash_lookup (host_uid_hash, data, len);
	return foo;
}

/* More than one host_decl can be returned by find_hosts_by_haddr or
   find_hosts_by_uid, and each host_decl can have multiple addresses.
   Loop through the list of hosts, and then for each host, through the
   list of addresses, looking for an address that's in the same shared
   network as the one specified.    Store the matching address through
   the addr pointer, update the host pointer to point at the host_decl
   that matched, and return the subnet that matched. */

struct subnet *find_host_for_network (host, addr, share)
	struct host_decl **host;
	struct iaddr *addr;
	struct shared_network *share;
{
	int i;
	struct subnet *subnet;
	struct iaddr ip_address;
	struct host_decl *hp;
	struct data_string fixed_addr;

	memset (&fixed_addr, 0, sizeof fixed_addr);

	for (hp = *host; hp; hp = hp -> n_ipaddr) {
		if (!hp -> fixed_addr)
			continue;
		if (!evaluate_data_expression (&fixed_addr, (struct packet *)0,
					       (struct option_state *)0,
					       (struct lease *)0,
					       hp -> fixed_addr -> expression))
			continue;
		for (i = 0; i < fixed_addr.len; i += 4) {
			ip_address.len = 4;
			memcpy (ip_address.iabuf,
				fixed_addr.data + i, 4);
			subnet = find_grouped_subnet (share, ip_address);
			if (subnet) {
				*addr = ip_address;
				*host = hp;
				data_string_forget (&fixed_addr,
						    "find_host_for_network");
				return subnet;
			}
		}
		data_string_forget (&fixed_addr, "find_host_for_network");
	}
	return (struct subnet *)0;
}

void new_address_range (low, high, subnet, pool)
	struct iaddr low, high;
	struct subnet *subnet;
	struct pool *pool;
{
	struct lease *address_range, *lp, *plp;
	struct iaddr net;
	int min, max, i;
	char lowbuf [16], highbuf [16], netbuf [16];
	struct shared_network *share = subnet -> shared_network;

	/* All subnets should have attached shared network structures. */
	if (!share) {
		strcpy (netbuf, piaddr (subnet -> net));
		log_fatal ("No shared network for network %s (%s)",
		       netbuf, piaddr (subnet -> netmask));
	}

	/* Initialize the hash table if it hasn't been done yet. */
	if (!lease_uid_hash) {
		lease_uid_hash = new_hash ();
		if (!lease_uid_hash)
			log_fatal ("Can't allocate lease/uid hash");
	}
	if (!lease_ip_addr_hash) {
		lease_ip_addr_hash = new_hash ();
		if (!lease_uid_hash)
			log_fatal ("Can't allocate lease/ip hash");
	}
	if (!lease_hw_addr_hash) {
		lease_hw_addr_hash = new_hash ();
		if (!lease_uid_hash)
			log_fatal ("Can't allocate lease/hw hash");
	}

	/* Make sure that high and low addresses are in same subnet. */
	net = subnet_number (low, subnet -> netmask);
	if (!addr_eq (net, subnet_number (high, subnet -> netmask))) {
		strcpy (lowbuf, piaddr (low));
		strcpy (highbuf, piaddr (high));
		strcpy (netbuf, piaddr (subnet -> netmask));
		log_fatal ("Address range %s to %s, netmask %s spans %s!",
		       lowbuf, highbuf, netbuf, "multiple subnets");
	}

	/* Make sure that the addresses are on the correct subnet. */
	if (!addr_eq (net, subnet -> net)) {
		strcpy (lowbuf, piaddr (low));
		strcpy (highbuf, piaddr (high));
		strcpy (netbuf, piaddr (subnet -> netmask));
		log_fatal ("Address range %s to %s not on net %s/%s!",
		       lowbuf, highbuf, piaddr (subnet -> net), netbuf);
	}

	/* Get the high and low host addresses... */
	max = host_addr (high, subnet -> netmask);
	min = host_addr (low, subnet -> netmask);

	/* Allow range to be specified high-to-low as well as low-to-high. */
	if (min > max) {
		max = min;
		min = host_addr (high, subnet -> netmask);
	}

	/* Get a lease structure for each address in the range. */
	address_range = new_leases (max - min + 1, "new_address_range");
	if (!address_range) {
		strcpy (lowbuf, piaddr (low));
		strcpy (highbuf, piaddr (high));
		log_fatal ("No memory for address range %s-%s.", lowbuf, highbuf);
	}
	memset (address_range, 0, (sizeof *address_range) * (max - min + 1));

	/* Fill in the last lease if it hasn't been already... */
	if (!pool -> last_lease) {
		pool -> last_lease = &address_range [0];
	}

	/* Fill out the lease structures with some minimal information. */
	for (i = 0; i < max - min + 1; i++) {
		address_range [i].ip_addr =
			ip_addr (subnet -> net, subnet -> netmask, i + min);
		address_range [i].starts =
			address_range [i].timestamp = MIN_TIME;
		address_range [i].ends = MIN_TIME;
		address_range [i].subnet = subnet;
		address_range [i].pool = pool;
		address_range [i].billing_class = (struct class *)0;
		address_range [i].flags = 0;

		/* Link this entry into the list. */
		address_range [i].next = pool -> leases;
		address_range [i].prev = (struct lease *)0;
		pool -> leases = &address_range [i];
		if (address_range [i].next)
			address_range [i].next -> prev = pool -> leases;
		add_hash (lease_ip_addr_hash,
			  address_range [i].ip_addr.iabuf,
			  address_range [i].ip_addr.len,
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
			address_range [lhost - i].hostname = lp -> hostname;
			address_range [lhost - i].client_hostname =
				lp -> client_hostname;
			address_range [lhost - i].ddns_fwd_name =
				lp -> ddns_fwd_name;
			address_range [lhost - i].ddns_rev_name =
				lp -> ddns_rev_name;
			supersede_lease (&address_range [lhost - i], lp, 0);
			free_lease (lp, "new_address_range");
		} else
			plp = lp;
	}
}

struct subnet *find_subnet (addr)
	struct iaddr addr;
{
	struct subnet *rv;

	for (rv = subnets; rv; rv = rv -> next_subnet) {
		if (addr_eq (subnet_number (addr, rv -> netmask), rv -> net))
			return rv;
	}
	return (struct subnet *)0;
}

struct subnet *find_grouped_subnet (share, addr)
	struct shared_network *share;
	struct iaddr addr;
{
	struct subnet *rv;

	for (rv = share -> subnets; rv; rv = rv -> next_sibling) {
		if (addr_eq (subnet_number (addr, rv -> netmask), rv -> net))
			return rv;
	}
	return (struct subnet *)0;
}

int subnet_inner_than (subnet, scan, warnp)
	struct subnet *subnet, *scan;
	int warnp;
{
	if (addr_eq (subnet_number (subnet -> net, scan -> netmask),
		     scan -> net) ||
	    addr_eq (subnet_number (scan -> net, subnet -> netmask),
		     subnet -> net)) {
		char n1buf [16];
		int i, j;
		for (i = 0; i < 32; i++)
			if (subnet -> netmask.iabuf [3 - (i >> 3)]
			    & (1 << (i & 7)))
				break;
		for (j = 0; j < 32; j++)
			if (scan -> netmask.iabuf [3 - (j >> 3)] &
			    (1 << (j & 7)))
				break;
		strcpy (n1buf, piaddr (subnet -> net));
		if (warnp)
			log_error ("%ssubnet %s/%d conflicts with subnet %s/%d",
			      "Warning: ", n1buf, 32 - i,
			      piaddr (scan -> net), 32 - j);
		if (i < j)
			return 1;
	}
	return 0;
}

/* Enter a new subnet into the subnet list. */
void enter_subnet (subnet)
	struct subnet *subnet;
{
	struct subnet *scan, *prev = (struct subnet *)0;

	/* Check for duplicates... */
	for (scan = subnets; scan; scan = scan -> next_subnet) {
		/* When we find a conflict, make sure that the
		   subnet with the narrowest subnet mask comes
		   first. */
		if (subnet_inner_than (subnet, scan, 1)) {
			if (prev) {
				prev -> next_subnet = subnet; 
			} else
				subnets = subnet;
			subnet -> next_subnet = scan;
			return;
		}
		prev = scan;
	}

	/* XXX use the BSD radix tree code instead of a linked list. */
	subnet -> next_subnet = subnets;
	subnets = subnet;
}
	
/* Enter a new shared network into the shared network list. */

void enter_shared_network (share)
	struct shared_network *share;
{
	/* XXX Sort the nets into a balanced tree to make searching quicker. */
	share -> next = shared_networks;
	shared_networks = share;
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
			log_fatal ("No memory for lease %s\n",
			       piaddr (lease -> ip_addr));
		}
		*comp = *lease;
		comp -> next = dangling_leases;
		comp -> prev = (struct lease *)0;
		dangling_leases = comp;
	} else {
		/* Record the hostname information in the lease. */
		comp -> hostname = lease -> hostname;
		comp -> client_hostname = lease -> client_hostname;
		comp -> ddns_fwd_name = lease -> ddns_fwd_name;
		comp -> ddns_rev_name = lease -> ddns_rev_name;
		supersede_lease (comp, lease, 0);
	}
}

/* Replace the data in an existing lease with the data in a new lease;
   adjust hash tables to suit, and insertion sort the lease into the
   list of leases by expiry time so that we can always find the oldest
   lease. */

int supersede_lease (comp, lease, commit)
	struct lease *comp, *lease;
	int commit;
{
	int enter_uid = 0;
	int enter_hwaddr = 0;
	struct lease *lp;

	/* Static leases are not currently kept in the database... */
	if (lease -> flags & STATIC_LEASE)
		return 1;

	/* If the existing lease hasn't expired and has a different
	   unique identifier or, if it doesn't have a unique
	   identifier, a different hardware address, then the two
	   leases are in conflict.  If the existing lease has a uid
	   and the new one doesn't, but they both have the same
	   hardware address, and dynamic bootp is allowed on this
	   lease, then we allow that, in case a dynamic BOOTP lease is
	   requested *after* a DHCP lease has been assigned. */

	if (!(lease -> flags & ABANDONED_LEASE) &&
	    comp -> ends > cur_time &&
	    (((comp -> uid && lease -> uid) &&
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
		log_error ("Lease conflict at %s",
		      piaddr (comp -> ip_addr));
		return 0;
	}

	/* If there's a Unique ID, dissociate it from the hash
	   table and free it if necessary. */
	if (comp -> uid) {
		uid_hash_delete (comp);
		enter_uid = 1;
		if (comp -> uid != &comp -> uid_buf [0]) {
			free (comp -> uid);
			comp -> uid_max = 0;
			comp -> uid_len = 0;
		}
		comp -> uid = (unsigned char *)0;
	} else
		enter_uid = 1;
	
	if (comp -> hardware_addr.htype &&
	    ((comp -> hardware_addr.hlen !=
	      lease -> hardware_addr.hlen) ||
	     (comp -> hardware_addr.htype !=
	      lease -> hardware_addr.htype) ||
	     memcmp (comp -> hardware_addr.haddr,
		     lease -> hardware_addr.haddr,
		     comp -> hardware_addr.hlen))) {
		hw_hash_delete (comp);
		enter_hwaddr = 1;
	} else if (!comp -> hardware_addr.htype)
		enter_hwaddr = 1;
	
	/* If the lease has been billed to a class, remove the billing. */
	if (comp -> billing_class &&
	    comp -> billing_class != lease -> billing_class)
		unbill_class (comp, comp -> billing_class);

	/* Copy the data files, but not the linkages. */
	comp -> starts = lease -> starts;
	if (lease -> uid) {
		if (lease -> uid_len < sizeof (lease -> uid_buf)) {
			memcpy (comp -> uid_buf,
				lease -> uid, lease -> uid_len);
			comp -> uid = &comp -> uid_buf [0];
			comp -> uid_max = sizeof comp -> uid_buf;
		} else if (lease -> uid != &lease -> uid_buf [0]) {
			comp -> uid = lease -> uid;
			comp -> uid_max = lease -> uid_max;
			lease -> uid = (unsigned char *)0;
			lease -> uid_max = 0;
		} else {
			log_fatal ("corrupt lease uid."); /* XXX */
		}
	} else {
		comp -> uid = (unsigned char *)0;
		comp -> uid_max = 0;
	}
	comp -> uid_len = lease -> uid_len;
	comp -> host = lease -> host;
	comp -> hardware_addr = lease -> hardware_addr;
	comp -> flags = ((lease -> flags & ~PERSISTENT_FLAGS) |
			 (comp -> flags & ~EPHEMERAL_FLAGS));
	
	/* Record the lease in the uid hash if necessary. */
	if (enter_uid && lease -> uid) {
		uid_hash_add (comp);
	}
	
	/* Record it in the hardware address hash if necessary. */
	if (enter_hwaddr && lease -> hardware_addr.htype) {
		hw_hash_add (comp);
	}
	
	/* Remove the lease from its current place in the 
	   timeout sequence. */
	if (comp -> prev) {
		comp -> prev -> next = comp -> next;
	} else {
		comp -> pool -> leases = comp -> next;
	}
	if (comp -> next) {
		comp -> next -> prev = comp -> prev;
	}
	if (comp -> pool -> last_lease == comp) {
		comp -> pool -> last_lease = comp -> prev;
	}
	
	/* Find the last insertion point... */
	if (comp == comp -> pool -> insertion_point ||
	    !comp -> pool -> insertion_point) {
		lp = comp -> pool -> leases;
	} else {
		lp = comp -> pool -> insertion_point;
	}
	
	if (!lp) {
		/* Nothing on the list yet?    Just make comp the
		   head of the list. */
		comp -> pool -> leases = comp;
		comp -> pool -> last_lease = comp;
	} else if (lp -> ends > lease -> ends) {
		/* Skip down the list until we run out of list
		   or find a place for comp. */
		while (lp -> next && lp -> ends > lease -> ends) {
			lp = lp -> next;
		}
		if (lp -> ends > lease -> ends) {
			/* If we ran out of list, put comp at the end. */
			lp -> next = comp;
			comp -> prev = lp;
			comp -> next = (struct lease *)0;
			comp -> pool -> last_lease = comp;
		} else {
			/* If we didn't, put it between lp and
			   the previous item on the list. */
			if ((comp -> prev = lp -> prev))
				comp -> prev -> next = comp;
			else
				comp -> pool -> leases = comp;
			comp -> next = lp;
			lp -> prev = comp;
		}
	} else {
		/* Skip up the list until we run out of list
		   or find a place for comp. */
		while (lp -> prev && lp -> ends < lease -> ends) {
			lp = lp -> prev;
		}
		if (lp -> ends < lease -> ends) {
			/* If we ran out of list, put comp at the beginning. */
			lp -> prev = comp;
			comp -> next = lp;
			comp -> prev = (struct lease *)0;
			comp -> pool -> leases = comp;
		} else {
			/* If we didn't, put it between lp and
			   the next item on the list. */
			if ((comp -> next = lp -> next))
				comp -> next -> prev = comp;
			else
				comp -> pool -> last_lease = comp;
			comp -> prev = lp;
			lp -> next = comp;
		}
	}
	comp -> pool -> insertion_point = comp;
	comp -> ends = lease -> ends;

	/* If there's an expiry event on this lease, process it or
	   queue it. */
	if (comp -> ddns_fwd_name) {
		if (comp -> ends < cur_time) {
#if defined (NSUPDATE)
			nsupdate (comp, (struct lease_state *)0,
				  (struct packet *)0, DELETE);
#endif
		} else {
			/* If this is the next lease that will timeout on the
			   pool, zap the old timeout and set the timeout on
			   this pool to the time that the lease ends.
			   
			   We do not actually set the timeout unless commit is
			   true - we don't want to thrash the timer queue when
			   reading the lease database.  Instead, the database
			   code calls the expiry event on each pool after
			   reading in the lease file, and the expiry code sets
			   the timer if there's anything left to expire after
			   it's run any outstanding expiry events on the
			   pool. */
			if (comp -> pool) {
			    if (!comp -> pool -> next_expiry) {
				comp -> pool -> next_expiry = comp;
				if (commit)
					add_timeout (comp -> ends,
						     pool_timer, comp -> pool);
			    } else if (comp -> ends <
				       comp -> pool -> next_expiry -> ends) {
				if (commit)
					add_timeout (comp -> ends,
						     pool_timer, comp -> pool);
			    }
			}
		}
	}

	/* Return zero if we didn't commit the lease to permanent storage;
	   nonzero if we did. */
	return commit && write_lease (comp) && commit_leases ();
}

/* Release the specified lease and re-hash it as appropriate. */

void release_lease (lease, packet)
	struct lease *lease;
	struct packet *packet;
{
	struct lease lt;

#if defined (NSUPDATE)
	nsupdate (lease, (struct lease_state *)0, packet, DELETE);
#endif

	lt = *lease;
	if (lt.ends > cur_time) {
		lt.ends = cur_time;
		lt.billing_class = (struct class *)0;
		supersede_lease (lease, &lt, 1);
	}
}

/* Abandon the specified lease (set its timeout to infinity and its
   particulars to zero, and re-hash it as appropriate. */

void abandon_lease (lease, packet, message)
	struct lease *lease;
	struct packet *packet;
	char *message;
{
	struct lease lt;

#if defined (NSUPDATE)
	nsupdate (lease, (struct lease_state *)0, packet, DELETE);
#endif

	lease -> flags |= ABANDONED_LEASE;
	lt = *lease;
	lt.ends = cur_time; /* XXX */
	log_error ("Abandoning IP address %s: %s",
	      piaddr (lease -> ip_addr), message);
	lt.hardware_addr.htype = 0;
	lt.hardware_addr.hlen = 0;
	lt.uid = (unsigned char *)0;
	lt.uid_len = 0;
	lt.billing_class = (struct class *)0;
	supersede_lease (lease, &lt, 1);
}

/* Abandon the specified lease (set its timeout to infinity and its
   particulars to zero, and re-hash it as appropriate. */

void dissociate_lease (lease, packet)
	struct lease *lease;
	struct packet *packet;
{
	struct lease lt;

#if defined (NSUPDATE)
	nsupdate (lease, (struct lease_state *)0, packet, DELETE);
#endif

	lt = *lease;
	if (lt.ends > cur_time)
		lt.ends = cur_time;
	lt.hardware_addr.htype = 0;
	lt.hardware_addr.hlen = 0;
	lt.uid = (unsigned char *)0;
	lt.uid_len = 0;
	lt.billing_class = (struct class *)0;
	supersede_lease (lease, &lt, 1);
}

/* Timer called when a lease in a particular pool expires. */
void pool_timer (vpool)
	void *vpool;
{
	struct pool *pool;
	struct lease *lease;

	pool = (struct pool *)vpool;
	for (lease = pool -> next_expiry; lease; lease = lease -> prev) {
		/* Stop processing when we get to the first lease that has not
                   yet expired. */
		if (lease -> ends > cur_time)
			break;
		/* Skip entries that aren't set to expire. */
		if (!lease -> ddns_fwd_name)
			continue;

#if defined (NSUPDATE)
		nsupdate (lease, (struct lease_state *)0, (struct packet *)0,
			  DELETE);
#endif
		if (!write_lease (lease)) {
			log_error ("Error updating lease %s after expiry",
				   piaddr (lease -> ip_addr));
		}
		if (!commit_leases ()) {
			log_error ("Error committing after writing lease %s",
				   piaddr (lease -> ip_addr));
		}
	}
	pool -> next_expiry = lease;
	if (lease)
		add_timeout (lease -> ends, pool_timer, pool);
}

void expire_all_pools ()
{
	struct shared_network *s;
	struct pool *p;
	struct hash_bucket *hb;
	int i;

	/* Loop through each pool in each shared network and call the
	   expiry routine on the pool. */
	for (s = shared_networks; s; s = s -> next)
		for (p = s -> pools; p; p = p -> next)
			pool_timer (p);
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

struct lease *find_lease_by_hw_addr (hwaddr, hwlen)
	unsigned char *hwaddr;
	int hwlen;
{
	struct lease *lease = (struct lease *)hash_lookup (lease_hw_addr_hash,
							   hwaddr, hwlen);
	return lease;
}

/* Add the specified lease to the uid hash. */

void uid_hash_add (lease)
	struct lease *lease;
{
	struct lease *head =
		find_lease_by_uid (lease -> uid, lease -> uid_len);
	struct lease *scan;

	/* If it's not in the hash, just add it. */
	if (!head)
		add_hash (lease_uid_hash, lease -> uid,
			  lease -> uid_len, (unsigned char *)lease);
	else {
		/* Otherwise, attach it to the end of the list. */
		for (scan = head; scan -> n_uid; scan = scan -> n_uid)
			;
		scan -> n_uid = lease;
	}
}

/* Delete the specified lease from the uid hash. */

void uid_hash_delete (lease)
	struct lease *lease;
{
	struct lease *head =
		find_lease_by_uid (lease -> uid, lease -> uid_len);
	struct lease *scan;

	/* If it's not in the hash, we have no work to do. */
	if (!head) {
		lease -> n_uid = (struct lease *)0;
		return;
	}

	/* If the lease we're freeing is at the head of the list,
	   remove the hash table entry and add a new one with the
	   next lease on the list (if there is one). */
	if (head == lease) {
		delete_hash_entry (lease_uid_hash,
				   lease -> uid, lease -> uid_len);
		if (lease -> n_uid)
			add_hash (lease_uid_hash,
				  lease -> n_uid -> uid,
				  lease -> n_uid -> uid_len,
				  (unsigned char *)(lease -> n_uid));
	} else {
		/* Otherwise, look for the lease in the list of leases
		   attached to the hash table entry, and remove it if
		   we find it. */
		for (scan = head; scan -> n_uid; scan = scan -> n_uid) {
			if (scan -> n_uid == lease) {
				scan -> n_uid = scan -> n_uid -> n_uid;
				break;
			}
		}
	}
	lease -> n_uid = (struct lease *)0;
}

/* Add the specified lease to the hardware address hash. */

void hw_hash_add (lease)
	struct lease *lease;
{
	struct lease *head =
		find_lease_by_hw_addr (lease -> hardware_addr.haddr,
				       lease -> hardware_addr.hlen);
	struct lease *scan;

	/* If it's not in the hash, just add it. */
	if (!head)
		add_hash (lease_hw_addr_hash,
			  lease -> hardware_addr.haddr,
			  lease -> hardware_addr.hlen,
			  (unsigned char *)lease);
	else {
		/* Otherwise, attach it to the end of the list. */
		for (scan = head; scan -> n_hw; scan = scan -> n_hw)
			;
		scan -> n_hw = lease;
	}
}

/* Delete the specified lease from the hardware address hash. */

void hw_hash_delete (lease)
	struct lease *lease;
{
	struct lease *head =
		find_lease_by_hw_addr (lease -> hardware_addr.haddr,
				       lease -> hardware_addr.hlen);
	struct lease *scan;

	/* If it's not in the hash, we have no work to do. */
	if (!head) {
		lease -> n_hw = (struct lease *)0;
		return;
	}

	/* If the lease we're freeing is at the head of the list,
	   remove the hash table entry and add a new one with the
	   next lease on the list (if there is one). */
	if (head == lease) {
		delete_hash_entry (lease_hw_addr_hash,
				   lease -> hardware_addr.haddr,
				   lease -> hardware_addr.hlen);
		if (lease -> n_hw)
			add_hash (lease_hw_addr_hash,
				  lease -> n_hw -> hardware_addr.haddr,
				  lease -> n_hw -> hardware_addr.hlen,
				  (unsigned char *)(lease -> n_hw));
	} else {
		/* Otherwise, look for the lease in the list of leases
		   attached to the hash table entry, and remove it if
		   we find it. */
		for (scan = head; scan -> n_hw; scan = scan -> n_hw) {
			if (scan -> n_hw == lease) {
				scan -> n_hw = scan -> n_hw -> n_hw;
				break;
			}
		}
	}
	lease -> n_hw = (struct lease *)0;
}

struct group *clone_group (group, caller)
	struct group *group;
	char *caller;
{
	struct group *g = new_group (caller);
	if (!g)
		log_fatal ("%s: can't allocate new group", caller);
	*g = *group;
	g -> statements = (struct executable_statement *)0;
	g -> next = group;
	return g;
}

/* Write all interesting leases to permanent storage. */

void write_leases ()
{
	struct lease *l;
	struct shared_network *s;
	struct pool *p;

	for (s = shared_networks; s; s = s -> next) {
		for (p = s -> pools; p; p = p -> next) {
			for (l = p -> leases; l; l = l -> next) {
				if (l -> hardware_addr.hlen ||
				    l -> uid_len ||
				    (l -> flags & ABANDONED_LEASE))
					if (!write_lease (l))
						log_fatal ("Can't rewrite %s",
						       "lease database");
			}
		}
	}
	if (!commit_leases ())
		log_fatal ("Can't commit leases to new database: %m");
}

void dump_subnets ()
{
	struct lease *l;
	struct shared_network *s;
	struct subnet *n;
	struct pool *p;

	log_info ("Subnets:");
	for (n = subnets; n; n = n -> next_subnet) {
		log_debug ("  Subnet %s", piaddr (n -> net));
		log_debug ("     netmask %s",
		       piaddr (n -> netmask));
	}
	log_info ("Shared networks:");
	for (s = shared_networks; s; s = s -> next) {
		log_info ("  %s", s -> name);
		for (p = s -> pools; p; p = p -> next) {
			for (l = p -> leases; l; l = l -> next) {
				print_lease (l);
			}
			log_debug ("Last Lease:");
			print_lease (p -> last_lease);
		}
	}
}
