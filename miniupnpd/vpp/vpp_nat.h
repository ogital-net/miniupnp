/* MiniUPnP project
 * VPP NAT44-ED backend -- public declarations
 *
 * Implements the commonrdr.h interface against libvapiclient /
 * vapi/nat44_ed.api.vapi.h.
 */
#ifndef VPP_NAT_H_INCLUDED
#define VPP_NAT_H_INCLUDED

#include <sys/types.h>  /* u_int64_t */
#include <sys/socket.h> /* struct sockaddr -- needed by get_nat_ext_addr */
#include <stdint.h>     /* uint8_t */

/* All public symbols are those required by commonrdr.h; nothing extra
 * is exported from this backend. */

int  init_redirect(void);
void shutdown_redirect(void);

int  get_redirect_rule_count(const char *ifname);

int  get_redirect_rule(const char *ifname,
                       unsigned short eport, int proto,
                       char *iaddr, int iaddrlen,
                       unsigned short *iport,
                       char *desc, int desclen,
                       char *rhost, int rhostlen,
                       unsigned int *timestamp,
                       u_int64_t *packets,
                       u_int64_t *bytes);

int  get_redirect_rule_by_index(int index,
                                char *ifname,
                                unsigned short *eport,
                                char *iaddr, int iaddrlen,
                                unsigned short *iport,
                                int *proto,
                                char *desc, int desclen,
                                char *rhost, int rhostlen,
                                unsigned int *timestamp,
                                u_int64_t *packets,
                                u_int64_t *bytes);

unsigned short *get_portmappings_in_range(unsigned short startport,
                                          unsigned short endport,
                                          int proto,
                                          unsigned int *number);

int  add_redirect_rule2(const char *ifname,
                        const char *rhost,
                        unsigned short eport,
                        const char *iaddr,
                        unsigned short iport,
                        int proto,
                        const char *desc,
                        unsigned int timestamp);

int  add_filter_rule2(const char *ifname,
                      const char *rhost,
                      const char *iaddr,
                      unsigned short eport,
                      unsigned short iport,
                      int proto,
                      const char *desc);

int  delete_redirect_and_filter_rules(unsigned short eport, int proto);

int  update_portmapping(const char *ifname,
                        unsigned short eport, int proto,
                        unsigned short iport,
                        const char *desc,
                        unsigned int timestamp);

int  update_portmapping_desc_timestamp(const char *ifname,
                                       unsigned short eport, int proto,
                                       const char *desc,
                                       unsigned int timestamp);

int  delete_filter_rule(const char *ifname, unsigned short port, int proto);

/* PCP PEER -- VPP NAT44-ED does not maintain a separate peer-mapping table;
 * these stubs satisfy the PCP server's link-time requirements.
 * get_peer_rule_by_index always returns -1 (empty table).
 * add_peer_redirect_rule2 stores the mapping as a regular static NAT44-ED
 * entry (same as add_redirect_rule2), ignoring the peer-side address.
 * get_nat_ext_addr is a netfilter-specific conntrack helper; it always
 * returns 0 (not found) for the VPP backend. */
int  get_peer_rule_by_index(int index,
                             char *ifname,
                             unsigned short *eport,
                             char *iaddr, int iaddrlen,
                             unsigned short *iport,
                             int *proto,
                             char *desc, int desclen,
                             char *rhost, int rhostlen,
                             unsigned short *rport,
                             unsigned int *timestamp,
                             u_int64_t *packets,
                             u_int64_t *bytes);

int  add_peer_redirect_rule2(const char *ifname,
                              const char *rhost, unsigned short rport,
                              const char *eaddr, unsigned short eport,
                              const char *iaddr, unsigned short iport,
                              int proto,
                              const char *desc, unsigned int timestamp);

int  get_nat_ext_addr(struct sockaddr *src, struct sockaddr *dst,
                      uint8_t proto, struct sockaddr *ret_ext);

/* VPP connection keepalive support.
 *
 * VPP sends periodic memclnt_keepalive pings and prunes clients that don't
 * respond.  vpp_get_event_fd() returns the VAPI socket fd suitable for
 * select()/poll(); when readable, call vpp_dispatch_events() to answer
 * keepalives (and drain any other pending messages).
 *
 * Returns -1 if not currently connected (caller should skip FD_SET). */
int  vpp_get_event_fd(void);

/* Drain pending VPP messages (answers keepalives).  Non-blocking.
 * Call when select() reports the event fd as readable. */
void vpp_dispatch_events(void);

#endif /* VPP_NAT_H_INCLUDED */
