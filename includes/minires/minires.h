/*
 * Copyright (c) 2000 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#include "cdefs.h"
#include "osdep.h"

#include "minires/resolv.h"
#include "minires/res_update.h"

/*
 * Based on the Dynamic DNS reference implementation by Viraj Bais
 * <viraj_bais@ccm.fm.intel.com>
 */

extern const struct res_sym __p_type_syms[];
extern time_t cur_time;

int dn_comp (const char *,
	     unsigned char *, unsigned, unsigned char **, unsigned char **);
int loc_aton (const char *, u_char *);
int sym_ston (const struct res_sym *, const char *, int *);
void  res_buildservicelist (void);
void res_destroyservicelist (void);
void res_buildprotolist(void);
void res_destroyprotolist(void);
int res_servicenumber(const char *);
int res_protocolnumber(const char *);
const char *res_protocolname(int);
const char *res_servicename(u_int16_t, const char *);
u_int32_t ns_datetosecs __P((const char *cp, int *errp));
int b64_pton (char const *, unsigned char *, size_t);
int res_ninit (res_state);
unsigned int res_randomid (void);
int res_findzonecut (res_state, const char *, ns_class, int,
		     char *, size_t, struct in_addr *, int);
int res_nsend (res_state,
	       unsigned char *, unsigned, unsigned char *, unsigned);
int res_nsendsigned (res_state, unsigned char *,
		     unsigned, ns_tsig_key *, unsigned char *, unsigned);
int ns_samename (const char *, const char *);
int res_nameinquery (const char *, int, int,
		     const unsigned char *, const unsigned char *);
int res_queriesmatch (const unsigned char *, const unsigned char *,
		      const unsigned char *, const unsigned char *);
int dn_expand (const unsigned char *,
	       const unsigned char *, const unsigned char *, char *, unsigned);
unsigned int ns_get16 (const unsigned char *);
void res_close (void);
void res_nclose (res_state);
int res_ourserver_p (const res_state, const struct sockaddr_in *);
int ns_sign (unsigned char *, unsigned *,
	     unsigned, int, void *, const unsigned char *,
	     unsigned, unsigned char *, unsigned *, time_t);
const char *p_class (int);
const char *p_section (int section, int opcode);
int ns_makecanon (const char *, char *, size_t);
int ns_parserr (ns_msg *, ns_sect, int, ns_rr *);
int ns_samedomain (const char *, const char *);
int ns_name_uncompress __P((const u_char *, const u_char *,
			    const u_char *, char *, size_t));
int res_nmkquery (res_state, int,
		  const char *, ns_class, ns_type, const unsigned char *,
		  unsigned, const unsigned char *, unsigned char *, unsigned);
int ns_initparse (const unsigned char *, unsigned, ns_msg *);
int res_nquery(res_state, const char *,
	       ns_class, ns_type, unsigned char *, unsigned anslen);
int res_nsearch(res_state, const char *,
		ns_class, ns_type, unsigned char *, unsigned);
const char *res_hostalias (const res_state, const char *, char *, size_t);
int res_nquerydomain(res_state, const char *, const char *,
		     ns_class class, ns_class type, unsigned char *, unsigned);

int res_mkupdate (ns_updrec *, unsigned char *, unsigned);
int res_update (ns_updrec *);
ns_updrec *res_mkupdrec (int, const char *, unsigned int,
			 unsigned int, unsigned long);
void res_freeupdrec (ns_updrec *);
int res_nmkupdate (res_state, ns_updrec *, unsigned char *, unsigned);
int res_nupdate (res_state, ns_updrec *, ns_tsig_key *);
int ns_skiprr(const unsigned char *, const unsigned char *, ns_sect, int);
int dn_skipname (const unsigned char *, const unsigned char *);
u_int32_t getULong (const unsigned char *);
int32_t getLong (const unsigned char *);
u_int32_t getUShort (const unsigned char *);
int32_t getShort (const unsigned char *);
u_int32_t getUChar (const unsigned char *);
void putULong (unsigned char *, u_int32_t);
void putLong (unsigned char *, int32_t);
void putUShort (unsigned char *, u_int32_t);
void putShort (unsigned char *, int32_t);
void putUChar (unsigned char *, u_int32_t);
int ns_name_ntol (const unsigned char *, unsigned char *, size_t);
int ns_sign_tcp_init (void *,
		      const unsigned char *, unsigned, ns_tcp_tsig_state *);
int ns_sign_tcp (unsigned char *,
		 unsigned *, unsigned, int, ns_tcp_tsig_state *, int);
int ns_name_ntop (const unsigned char *, char *, size_t);
int ns_name_pton (const char *, unsigned char *, size_t);
int ns_name_unpack (const unsigned char *, const unsigned char *,
		    const unsigned char *, unsigned char *, size_t);
int ns_name_pack (const unsigned char *, unsigned char *,
		  unsigned, const unsigned char **, const unsigned char **);
int ns_name_compress (const char *, unsigned char *,
		      size_t, const unsigned char **, const unsigned char **);
int ns_name_skip (const unsigned char **, const unsigned char *);
int ns_subdomain (const char *, const char *);
unsigned char *ns_find_tsig (unsigned char *, unsigned char *);
int ns_verify (unsigned char *, unsigned *, void *, const unsigned char *,
	       unsigned, unsigned char *, unsigned *, time_t *, int);
int ns_verify_tcp_init (void *,
		       const unsigned char *, unsigned, ns_tcp_tsig_state *);
int ns_verify_tcp (unsigned char *, unsigned *, ns_tcp_tsig_state *, int);
int b64_ntop (unsigned char const *, size_t, char *, size_t);



#define DprintQ(a,b,c,d)
#define Dprint(a,b)
#define Perror(a, b, c, d)
#define Aerror(a, b, c, d, e)
#define DPRINTF(x)

#define USE_MD5
