
static void		IpChecksum(struct ip *ip);
static void		UdpChecksum(struct ip *ip);
static u_int32_t	Checksum(u_int16_t *buf, int nwords);

struct raw_packet
{
  u_int16_t space;
  struct ether_header en_hdr;
  struct ip ip;
  struct udphdr udp;
  struct dhcp_packet dhcp;
};

int sendpkt (in_packet, raw, len, to, tolen)
  struct packet *in_packet;
  struct dhcp_packet *raw;
  size_t len;
  struct sockaddr *to;
  int tolen;
{
  int			i, k;
  struct iaddr		dest;
  struct subnet		*subnet;
  struct raw_packet	out_packet;
  struct raw_packet	*const pkt = &out_packet;

/* Find local subnet, or else forward to gateway */

  dest.len = 4;
  memcpy(&dest.iabuf, &((struct sockaddr_in *) to)->sin_addr, dest.len);
  if ((subnet = find_subnet(dest)) == NULL)
    return(sendto(in_packet->client_sock, raw, len, 0, to, tolen));

/* Find interface corresponding to subnet */

  for (i = 0; i < num_ifaces; i++)
  {
    for (k = 0; k < subnet->net.len
      && (dest.iabuf[k] & subnet->netmask.iabuf[k])
	== (subnet->net.iabuf[k] & subnet->netmask.iabuf[k]);
    k++);
    if (k == subnet->net.len)
      break;
  }
  if (i == num_ifaces)
    return(sendto(in_packet->client_sock, raw, len, 0, to, tolen));

/* EtherNet header */

  memset(pkt->en_hdr.ether_dhost, 0xff, sizeof(pkt->en_hdr.ether_dhost));
  memset(pkt->en_hdr.ether_shost, 0x00, sizeof(pkt->en_hdr.ether_shost));
  pkt->en_hdr.ether_type = ETHERTYPE_IP;

/* IP header (except for checksum) */

  pkt->ip.ip_v = 4;
  pkt->ip.ip_hl = 5;
  pkt->ip.ip_tos = IPTOS_LOWDELAY;
  pkt->ip.ip_len = htons(sizeof(pkt->ip) + sizeof(pkt->udp) + len);
  pkt->ip.ip_id = 0;
  pkt->ip.ip_off = 0;
  pkt->ip.ip_ttl = 16;
  pkt->ip.ip_p = IPPROTO_UDP;
  pkt->ip.ip_sum = 0;
  pkt->ip.ip_src = if_list[i].address;
  inet_aton("255.255.255.255", &pkt->ip.ip_dst);

/* UDP header */

  pkt->udp.uh_sport = htons(67);		/* XXX! */
  pkt->udp.uh_dport = in_packet->client_port;
  pkt->udp.uh_ulen = htons(sizeof(pkt->udp) + len);
  pkt->udp.uh_sum = 0;

/* DHCP packet */

  pkt->dhcp = *raw;

/* Compute checksums */

  UdpChecksum(&pkt->ip);
  IpChecksum(&pkt->ip);

/* Fire it off */

  if (write(if_list[i].bpf, &pkt->en_hdr,
      ntohs(pkt->ip.ip_len) + sizeof(pkt->en_hdr)) < 0)
    warn ("Can't deliver packet: write: %m");
  return(0);
}

/*
 * UdpChecksum()
 *
 * Recompute a UDP checksum on a packet
 *
 * UDP pseudo-header (prot = IPPROTO_UDP = 17):
 *
 *  | source IP address	       |
 *  | dest.  IP address	       |
 *  | zero | prot | UDP leng   |
 *
 */

static void
UdpChecksum(struct ip *ip)
{
  struct udphdr	*udp = (struct udphdr *) ((long *) ip + ip->ip_hl);
  u_int32_t	sum;

/* Pad with zero */

  if (ntohs(udp->uh_ulen) & 0x1)
    *((u_char *) udp + ntohs(udp->uh_ulen)) = 0;

/* Do pseudo-header first */

  sum = Checksum((u_int16_t *) &ip->ip_src, 4);
  sum += (u_int16_t) IPPROTO_UDP;
  sum += (u_int16_t) ntohs(udp->uh_ulen);

/* Now do UDP packet itself */

  udp->uh_sum = 0;
  sum += Checksum((u_int16_t *) udp,
	  ((u_int16_t) ntohs(udp->uh_ulen) + 1) >> 1);

/* Flip it & stick it */

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  sum = ~sum;

  udp->uh_sum = htons(sum);
}

/*
 * IpChecksum()
 *
 * Recompute an IP header checksum
 *
 */

static void
IpChecksum(struct ip *ip)
{
  u_int32_t	sum;

/* Sum up IP header words */

  ip->ip_sum = 0;
  sum = Checksum((u_int16_t *) ip, ip->ip_hl * 2);

/* Flip it & stick it */

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  sum = ~sum;

  ip->ip_sum = htons(sum);
}

/*
 * Checksum()
 *
 * Do the one's complement sum thing over a range of words
 * Ideally, this should get replaced by an assembly version.
 */

static u_int32_t
Checksum(u_int16_t *buf, int nwords)
{
  u_int32_t	sum = 0;

  while (nwords--)
    sum += (u_int16_t) ntohs(*buf++);
  return(sum);
}

