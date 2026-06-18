/* MiniUPnP project
 * VPP NAT44-ED backend
 *
 * Implements the commonrdr.h interface via libvapiclient in non-blocking
 * mode.  In VAPI_MODE_NONBLOCKING the typed wrappers only send the request
 * and return immediately; we drive the reply loop ourselves with a bounded
 * deadline so miniupnpd never hangs if VPP is unresponsive.
 *
 * The single VAPI connection is opened in init_redirect() and closed in
 * shutdown_redirect().  All other functions are called on the main thread
 * while the connection is held.
 *
 * VAPI headers are self-contained: each .api.vapi.h pulls in every type it
 * needs; no separate .json registration is required beyond the
 * DEFINE_VAPI_MSG_IDS_* macros below.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <vapi/vapi.h>
#include <vapi/nat44_ed.api.vapi.h>
#include <vapi/nat_types.api.vapi.h>
#include <vapi/interface.api.vapi.h>
#include <vapi/ip.api.vapi.h>

DEFINE_VAPI_MSG_IDS_NAT44_ED_API_JSON;
DEFINE_VAPI_MSG_IDS_INTERFACE_API_JSON;
DEFINE_VAPI_MSG_IDS_IP_API_JSON;

#include "../config.h"
#include "../macros.h"
#include "../commonrdr.h"
#include "vpp_init.h"

/* -----------------------------------------------------------------------
 * Module-level VAPI context
 * -------------------------------------------------------------------- */

static vapi_ctx_t g_vapi_ctx = NULL;

/* -----------------------------------------------------------------------
 * Connection management
 *
 * VPP prunes idle API clients that fail to respond to keepalive pings.
 * In VAPI_MODE_NONBLOCKING keepalives are only answered inside
 * vapi_dispatch_*(), which we only call when processing a UPnP request.
 * If miniupnpd is idle for longer than VPP's dead-client-scan interval
 * (~60s default), the connection is reaped.
 *
 * We detect this as a transport error from the dispatch loop and tear
 * down the stale context.  vapi_ensure_connected() lazily re-establishes
 * it before the next VAPI operation.
 * -------------------------------------------------------------------- */

static void vapi_drop_connection(void)
{
	if (!g_vapi_ctx)
		return;
	vapi_disconnect(g_vapi_ctx);
	vapi_ctx_free(g_vapi_ctx);
	g_vapi_ctx = NULL;
}

/* (Re-)connect to VPP.  Returns 0 on success.  Idempotent if already
 * connected. */
static int vapi_ensure_connected(void)
{
	vapi_error_e rv;

	if (g_vapi_ctx)
		return 0; /* already connected */

	if (vapi_ctx_alloc(&g_vapi_ctx) != VAPI_OK) {
		syslog(LOG_ERR, "vpp: vapi_ctx_alloc failed");
		g_vapi_ctx = NULL;
		return -1;
	}

	rv = vapi_connect_ex(g_vapi_ctx,
	                     VPP_API_CLIENT_NAME,
	                     VPP_API_SOCK,
	                     32,    /* max_outstanding_requests */
	                     64,    /* response_queue_size */
	                     VAPI_MODE_NONBLOCKING,
	                     true,  /* handle_keepalives */
	                     true); /* use_uds */
	if (rv != VAPI_OK) {
		syslog(LOG_ERR, "vpp: vapi_connect_ex(%s) failed: %d",
		       VPP_API_SOCK, rv);
		vapi_ctx_free(g_vapi_ctx);
		g_vapi_ctx = NULL;
		return -1;
	}

	syslog(LOG_INFO, "vpp: connected to VPP at %s", VPP_API_SOCK);
	return 0;
}

/* -----------------------------------------------------------------------
 * Bounded dispatch loop (non-blocking mode)
 *
 * In VAPI_MODE_NONBLOCKING the typed wrappers send the request and return
 * immediately.  The caller must pump vapi_dispatch_one_timedwait() until
 * the reply callback sets *done, or the overall deadline expires.
 * Returns 0 on success, -1 on timeout or transport error.
 *
 * On transport error, tears down the connection so vapi_ensure_connected()
 * will re-establish it on the next call.
 * -------------------------------------------------------------------- */

static int vapi_dispatch_loop(volatile int *done)
{
	time_t deadline = time(NULL) + VPP_VAPI_REQUEST_TIMEOUT_S;

	while (!*done) {
		vapi_error_e rv =
			vapi_dispatch_one_timedwait(g_vapi_ctx,
				VPP_VAPI_DISPATCH_SLICE_S);

		if (rv == VAPI_OK)
			continue;

		if (rv == VAPI_EAGAIN) {
			if (time(NULL) >= deadline) {
				syslog(LOG_ERR,
				       "vpp: dispatch timed out after %ds "
				       "(VPP unresponsive)",
				       VPP_VAPI_REQUEST_TIMEOUT_S);
				vapi_drop_connection();
				return -1;
			}
			continue;
		}

		syslog(LOG_ERR, "vpp: dispatch error %d (connection lost?)",
		       rv);
		vapi_drop_connection();
		return -1;
	}

	return 0;
}

/* -----------------------------------------------------------------------
 * Timestamp list (mirrors nftnlrdr's in-memory approach)
 * -------------------------------------------------------------------- */

struct ts_entry {
	struct ts_entry *next;
	unsigned int     timestamp;
	unsigned short   eport;
	short            protocol;
};

static struct ts_entry *g_ts_list = NULL;

static void ts_add(unsigned short eport, int proto, unsigned int ts)
{
	struct ts_entry *e;
	for (e = g_ts_list; e; e = e->next) {
		if (e->eport == eport && e->protocol == (short)proto) {
			e->timestamp = ts;
			return;
		}
	}
	e = malloc(sizeof(*e));
	if (!e)
		return;
	e->eport     = eport;
	e->protocol  = (short)proto;
	e->timestamp = ts;
	e->next      = g_ts_list;
	g_ts_list    = e;
}

static unsigned int ts_get(unsigned short eport, int proto)
{
	struct ts_entry *e;
	for (e = g_ts_list; e; e = e->next)
		if (e->eport == eport && e->protocol == (short)proto)
			return e->timestamp;
	return 0;
}

static void ts_remove(unsigned short eport, int proto)
{
	struct ts_entry **pp = &g_ts_list;
	while (*pp) {
		if ((*pp)->eport == eport && (*pp)->protocol == (short)proto) {
			struct ts_entry *del = *pp;
			*pp = del->next;
			free(del);
			return;
		}
		pp = &(*pp)->next;
	}
}

/* -----------------------------------------------------------------------
 * Tag helpers
 * -------------------------------------------------------------------- */

/* Tag origin -- determines the prefix written into the 64-byte VPP tag. */
enum tag_origin {
	TAG_ORIGIN_UPNP,    /* "upnp:<desc>" */
	TAG_ORIGIN_NATPMP,  /* "natpmp"      */
	TAG_ORIGIN_PCP      /* "pcp:<desc>"  */
};

/* Build a tag string into buf[64].  Returns buf. */
static uint8_t *make_tag(uint8_t buf[64], const char *desc,
                         enum tag_origin origin)
{
	memset(buf, 0, 64);
	switch (origin) {
	case TAG_ORIGIN_UPNP:
		snprintf((char *)buf, 64, "upnp:%.58s", desc ? desc : "");
		break;
	case TAG_ORIGIN_PCP:
		snprintf((char *)buf, 64, "pcp:%.59s", desc ? desc : "");
		break;
	case TAG_ORIGIN_NATPMP:
		memcpy(buf, "natpmp", 6);
		break;
	}
	return buf;
}

/* A static mapping belongs to miniupnpd if its tag starts with a
 * recognised prefix written by this backend. */
static int tag_is_ours(const uint8_t tag[64])
{
	const char *t = (const char *)tag;
	return (strncmp(t, "upnp:", 5) == 0 ||
	        strncmp(t, "natpmp", 6) == 0 ||
	        strncmp(t, "pcp:",   4) == 0);
}

/* Determine the origin of an existing tag. */
static enum tag_origin tag_get_origin(const uint8_t tag[64])
{
	const char *t = (const char *)tag;
	if (strncmp(t, "upnp:", 5) == 0)  return TAG_ORIGIN_UPNP;
	if (strncmp(t, "pcp:",  4) == 0)  return TAG_ORIGIN_PCP;
	return TAG_ORIGIN_NATPMP;
}

/* Extract the description portion from a tag (strip the prefix). */
static void tag_to_desc(const uint8_t tag[64], char *buf, int buflen)
{
	const char *t = (const char *)tag;
	const char *p = NULL;
	if      (strncmp(t, "upnp:", 5) == 0)  p = t + 5;
	else if (strncmp(t, "natpmp", 6) == 0) p = t + 6;
	else if (strncmp(t, "pcp:",  4) == 0)  p = t + 4;
	else                                    p = t;
	if (buf && buflen > 0)
		snprintf(buf, (size_t)buflen, "%s", p);
}

/* -----------------------------------------------------------------------
 * VAPI callback context types
 * -------------------------------------------------------------------- */

/* nat44_show_running_config reply */
struct running_cfg_ctx {
	int retval;
	volatile int done;
};

/* nat44_add_del_static_mapping reply */
struct mapping_reply_ctx {
	int retval;
	volatile int done;
};

/* One static mapping record collected during a dump */
struct mapping_rec {
	uint8_t  local_ip[4];
	uint8_t  external_ip[4];
	uint16_t local_port;
	uint16_t external_port;
	uint8_t  protocol;
	uint8_t  tag[64];
};

/* Dump accumulator -- grows as needed */
struct dump_ctx {
	struct mapping_rec *recs;
	unsigned int        count;
	unsigned int        alloc;
	volatile int        done;
};

static int dump_ctx_push(struct dump_ctx *d,
                         const vapi_payload_nat44_static_mapping_details *r)
{
	struct mapping_rec *m;
	if (d->count >= d->alloc) {
		unsigned int na = d->alloc ? d->alloc * 2 : 16;
		struct mapping_rec *tmp = realloc(d->recs, na * sizeof(*tmp));
		if (!tmp)
			return -1;
		d->recs  = tmp;
		d->alloc = na;
	}
	m = &d->recs[d->count++];
	memcpy(m->local_ip,    r->local_ip_address,    4);
	memcpy(m->external_ip, r->external_ip_address, 4);
	/* VAPI _ntoh already byte-swaps multi-byte fields to host order;
	 * do NOT apply ntohs() again. */
	m->local_port    = r->local_port;
	m->external_port = r->external_port;
	m->protocol      = r->protocol;
	memcpy(m->tag, r->tag, 64);
	return 0;
}

static void dump_ctx_free(struct dump_ctx *d)
{
	free(d->recs);
	d->recs  = NULL;
	d->count = 0;
	d->alloc = 0;
}

/* -----------------------------------------------------------------------
 * VAPI callbacks
 * -------------------------------------------------------------------- */

static vapi_error_e
running_cfg_cb(vapi_ctx_t ctx, void *cdata,
               vapi_error_e rv, bool is_last,
               vapi_payload_nat44_show_running_config_reply *r)
{
	struct running_cfg_ctx *c = cdata;
	UNUSED(ctx); UNUSED(rv); UNUSED(is_last);
	if (r)
		c->retval = r->retval;
	c->done = 1;
	return VAPI_OK;
}

static vapi_error_e
mapping_reply_cb(vapi_ctx_t ctx, void *cdata,
                 vapi_error_e rv, bool is_last,
                 vapi_payload_nat44_add_del_static_mapping_reply *r)
{
	struct mapping_reply_ctx *c = cdata;
	UNUSED(ctx); UNUSED(rv); UNUSED(is_last);
	c->retval = r->retval;
	c->done = 1;
	return VAPI_OK;
}

static vapi_error_e
dump_cb(vapi_ctx_t ctx, void *cdata,
        vapi_error_e rv, bool is_last,
        vapi_payload_nat44_static_mapping_details *r)
{
	UNUSED(ctx); UNUSED(rv);
	if (is_last) {
		((struct dump_ctx *)cdata)->done = 1;
		return VAPI_OK;
	}
	/* nat44_static_mapping_dump only returns static mappings, so
	 * NAT_IS_STATIC is not necessarily echoed in the details flags.
	 * Do NOT filter on it. */
	if (!tag_is_ours(r->tag))
		return VAPI_OK;
	dump_ctx_push((struct dump_ctx *)cdata, r);
	return VAPI_OK;
}

/* -----------------------------------------------------------------------
 * VPP interface IP resolution (replaces kernel getifaddr)
 * -------------------------------------------------------------------- */

struct sw_if_resolve_ctx {
	const char *name;
	uint32_t    sw_if_index;
	int         found;
	volatile int done;
};

static vapi_error_e
sw_if_dump_cb(vapi_ctx_t ctx, void *cdata,
              vapi_error_e rv, bool is_last,
              vapi_payload_sw_interface_details *r)
{
	struct sw_if_resolve_ctx *c = cdata;
	UNUSED(ctx); UNUSED(rv);
	if (is_last) {
		c->done = 1;
		return VAPI_OK;
	}
	if (strcmp((const char *)r->interface_name, c->name) == 0) {
		c->sw_if_index = r->sw_if_index;
		c->found = 1;
	}
	return VAPI_OK;
}

struct ip_addr_ctx {
	struct in_addr addr;
	int            found;
	volatile int   done;
};

static vapi_error_e
ip_addr_dump_cb(vapi_ctx_t ctx, void *cdata,
                vapi_error_e rv, bool is_last,
                vapi_payload_ip_address_details *r)
{
	struct ip_addr_ctx *c = cdata;
	UNUSED(ctx); UNUSED(rv);
	if (is_last) {
		c->done = 1;
		return VAPI_OK;
	}
	if (r->prefix.address.af == ADDRESS_IP4 && !c->found) {
		memcpy(&c->addr.s_addr, r->prefix.address.un.ip4, 4);
		c->found = 1;
	}
	return VAPI_OK;
}

/* Resolve IPv4 address of a VPP interface by name.
 * Returns 0 on success, -1 on failure.
 * Non-static: also called from vpp/getifaddr_vpp.c to serve the generic
 * getifaddr() interface used by miniupnpd's SOAP, NAT-PMP, and the
 * disable_port_forwarding check. */
int vpp_getifaddr(const char *ifname, struct in_addr *addr)
{
	struct sw_if_resolve_ctx sw_ctx;
	struct ip_addr_ctx ip_ctx;
	vapi_msg_sw_interface_dump *sw_msg;
	vapi_msg_ip_address_dump *ip_msg;
	size_t namelen;
	vapi_error_e rv;
	int retries = 1;

retry:
	if (vapi_ensure_connected() < 0)
		return -1;

	/* Step 1: resolve interface name -> sw_if_index */
	memset(&sw_ctx, 0, sizeof(sw_ctx));
	sw_ctx.name = ifname;
	sw_ctx.sw_if_index = ~0u;

	namelen = strlen(ifname);
	sw_msg = vapi_alloc_sw_interface_dump(g_vapi_ctx, namelen);
	if (!sw_msg) {
		syslog(LOG_ERR, "vpp: vapi_alloc_sw_interface_dump failed");
		return -1;
	}

	sw_msg->payload.sw_if_index = ~0u;
	sw_msg->payload.name_filter_valid = true;
	sw_msg->payload.name_filter.length = namelen;
	memcpy(sw_msg->payload.name_filter.buf, ifname, namelen);

	rv = vapi_sw_interface_dump(g_vapi_ctx, sw_msg,
	                            sw_if_dump_cb, &sw_ctx);
	if (rv == VAPI_OK)
		rv = (vapi_dispatch_loop(&sw_ctx.done) == 0)
			? VAPI_OK : VAPI_EAGAIN;
	if (rv != VAPI_OK || !sw_ctx.found) {
		if (!g_vapi_ctx && retries-- > 0)
			goto retry;
		syslog(LOG_ERR, "vpp: interface '%s' not found (rv=%d found=%d)",
		       ifname, rv, sw_ctx.found);
		return -1;
	}

	/* Step 2: get IPv4 address of that interface */
	memset(&ip_ctx, 0, sizeof(ip_ctx));

	ip_msg = vapi_alloc_ip_address_dump(g_vapi_ctx);
	if (!ip_msg) {
		syslog(LOG_ERR, "vpp: vapi_alloc_ip_address_dump failed");
		return -1;
	}

	ip_msg->payload.sw_if_index = sw_ctx.sw_if_index;
	ip_msg->payload.is_ipv6 = false;

	rv = vapi_ip_address_dump(g_vapi_ctx, ip_msg,
	                          ip_addr_dump_cb, &ip_ctx);
	if (rv == VAPI_OK)
		rv = (vapi_dispatch_loop(&ip_ctx.done) == 0)
			? VAPI_OK : VAPI_EAGAIN;
	if (rv != VAPI_OK || !ip_ctx.found) {
		if (!g_vapi_ctx && retries-- > 0)
			goto retry;
		syslog(LOG_ERR,
		       "vpp: no IPv4 address on interface '%s' (sw_if_index %u)",
		       ifname, sw_ctx.sw_if_index);
		return -1;
	}

	*addr = ip_ctx.addr;
	return 0;
}

/* -----------------------------------------------------------------------
 * Internal: collect all our static mappings from VPP
 * Returns 0 on success, -1 on VAPI error.
 * Caller must call dump_ctx_free(d) when done.
 * -------------------------------------------------------------------- */
static int collect_mappings(struct dump_ctx *d)
{
	vapi_msg_nat44_static_mapping_dump *msg;
	vapi_error_e rv;
	int retries = 1;

retry:
	if (vapi_ensure_connected() < 0)
		return -1;

	memset(d, 0, sizeof(*d));

	msg = vapi_alloc_nat44_static_mapping_dump(g_vapi_ctx);
	if (!msg)
		return -1;

	rv = vapi_nat44_static_mapping_dump(
		g_vapi_ctx, msg, dump_cb, d);
	if (rv == VAPI_OK)
		rv = (vapi_dispatch_loop(&d->done) == 0)
			? VAPI_OK : VAPI_EAGAIN;
	if (rv != VAPI_OK) {
		dump_ctx_free(d);
		if (!g_vapi_ctx && retries-- > 0)
			goto retry;
		return -1;
	}
	return 0;
}

/* -----------------------------------------------------------------------
 * Internal: send one add/del static mapping request
 * -------------------------------------------------------------------- */
static int send_static_mapping(bool is_add,
                               const uint8_t local_ip[4],
                               const uint8_t ext_ip[4],
                               unsigned short local_port,
                               unsigned short ext_port,
                               int proto,
                               const uint8_t tag[64])
{
	struct mapping_reply_ctx rctx = { .retval = -1 };
	vapi_msg_nat44_add_del_static_mapping *msg;
	vapi_payload_nat44_add_del_static_mapping *p;
	vapi_error_e rv;
	int retries = 1;

retry:
	if (vapi_ensure_connected() < 0)
		return -1;

	rctx = (struct mapping_reply_ctx){ .retval = -1 };

	msg = vapi_alloc_nat44_add_del_static_mapping(g_vapi_ctx);
	if (!msg)
		return -1;

	p = &msg->payload;
	p->is_add               = is_add;
	p->flags                = NAT_IS_STATIC;
	memcpy(p->local_ip_address,    local_ip, 4);
	memcpy(p->external_ip_address, ext_ip,   4);
	p->protocol             = (uint8_t)proto;
	/* VAPI _hton byte-swaps multi-byte fields before sending;
	 * write host byte order here, do NOT use htons(). */
	p->local_port           = local_port;
	p->external_port        = ext_port;
	p->external_sw_if_index = ~0u;   /* use explicit external_ip_address */
	p->vrf_id               = 0;
	memcpy(p->tag, tag, 64);

	rv = vapi_nat44_add_del_static_mapping(
		g_vapi_ctx, msg, mapping_reply_cb, &rctx);
	if (rv == VAPI_OK)
		rv = (vapi_dispatch_loop(&rctx.done) == 0)
			? VAPI_OK : VAPI_EAGAIN;
	if (rv != VAPI_OK) {
		if (!g_vapi_ctx && retries-- > 0)
			goto retry;
		syslog(LOG_ERR, "vpp: vapi_nat44_add_del_static_mapping failed: %d", rv);
		return -1;
	}
	if (rctx.retval != 0) {
		syslog(LOG_ERR, "vpp: nat44_add_del_static_mapping retval=%d (is_add=%d)",
		       rctx.retval, (int)is_add);
		return -1;
	}
	return 0;
}

/* -----------------------------------------------------------------------
 * commonrdr.h -- init / shutdown
 * -------------------------------------------------------------------- */

int init_redirect(void)
{
	struct running_cfg_ctx rctx = { .retval = -1 };
	vapi_error_e rv;
	vapi_msg_nat44_show_running_config *msg;

	if (vapi_ensure_connected() < 0)
		return -1;

	/* Verify NAT44-ED is enabled */
	msg = vapi_alloc_nat44_show_running_config(g_vapi_ctx);
	if (!msg) {
		syslog(LOG_ERR, "vpp: vapi_alloc_nat44_show_running_config failed");
		vapi_drop_connection();
		return -1;
	}

	rv = vapi_nat44_show_running_config(g_vapi_ctx, msg,
	                                    running_cfg_cb, &rctx);
	if (rv == VAPI_OK)
		rv = (vapi_dispatch_loop(&rctx.done) == 0)
			? VAPI_OK : VAPI_EAGAIN;
	if (rv != VAPI_OK || rctx.retval != 0) {
		syslog(LOG_ERR,
		       "vpp: NAT44-ED not enabled (vapi_rv=%d retval=%d); "
		       "ensure 'nat44-ed enable' is configured in VPP",
		       rv, rctx.retval);
		vapi_disconnect(g_vapi_ctx);
		vapi_ctx_free(g_vapi_ctx);
		g_vapi_ctx = NULL;
		return -1;
	}

	syslog(LOG_INFO, "vpp: connected to VPP NAT44-ED at %s", VPP_API_SOCK);
	return 0;
}

void shutdown_redirect(void)
{
	struct ts_entry *e;
	if (!g_vapi_ctx)
		return;
	/* Free timestamp list */
	e = g_ts_list;
	while (e) {
		struct ts_entry *next = e->next;
		free(e);
		e = next;
	}
	g_ts_list = NULL;

	vapi_drop_connection();
	syslog(LOG_INFO, "vpp: disconnected from VPP");
}

/* -----------------------------------------------------------------------
 * Event fd for select() integration
 *
 * miniupnpd's main loop uses select() to multiplex HTTP, SSDP, and
 * NAT-PMP sockets.  By adding the VAPI fd to the read set and calling
 * vpp_dispatch_events() when it becomes readable, we answer VPP's
 * keepalive pings in real time -- preventing idle-timeout disconnects.
 * -------------------------------------------------------------------- */

int vpp_get_event_fd(void)
{
	int fd = -1;
	if (!g_vapi_ctx)
		return -1;
	if (vapi_get_fd(g_vapi_ctx, &fd) != VAPI_OK)
		return -1;
	return fd;
}

void vpp_dispatch_events(void)
{
	if (!g_vapi_ctx)
		return;
	/* Drain all pending messages (keepalives, stale replies, etc.)
	 * without blocking.  wait_time=0 means return immediately if
	 * nothing is pending. */
	vapi_error_e rv;
	int count = 0;
	do {
		rv = vapi_dispatch_one_timedwait(g_vapi_ctx, 0);
		if (rv == VAPI_OK)
			count++;
	} while (rv == VAPI_OK);

	if (count > 0)
		syslog(LOG_DEBUG, "vpp: dispatched %d event(s) (keepalive?)",
		       count);

	/* If the drain encountered a transport error, drop the connection
	 * so vapi_ensure_connected() will re-establish on next use. */
	if (rv != VAPI_OK && rv != VAPI_EAGAIN) {
		syslog(LOG_WARNING, "vpp: event dispatch error %d, dropping connection", rv);
		vapi_drop_connection();
	}
}

/* -----------------------------------------------------------------------
 * commonrdr.h -- add / delete
 * -------------------------------------------------------------------- */

/* Internal: resolve WAN IP, build tag, install static mapping, record
 * timestamp.  Shared by add_redirect_rule2 and add_peer_redirect_rule2. */
static int add_mapping_internal(const char *ifname,
                                unsigned short eport,
                                const char *iaddr,
                                unsigned short iport,
                                int proto,
                                const char *desc,
                                unsigned int timestamp,
                                enum tag_origin origin)
{
	struct in_addr wan_addr;
	struct in_addr ia;
	char wan_str[INET_ADDRSTRLEN];
	uint8_t local_ip[4], ext_ip[4];
	uint8_t tag[64];

	/* Resolve the WAN IP from the VPP interface (not from the kernel).
	 * The ext_ifname in miniupnpd.conf should be a VPP interface name
	 * (e.g. GigabitEthernet0/0/0, TenGigabitEthernet0/0/0, etc.).
	 * Note: use_ext_ip_addr (ext_ip= / STUN) is intentionally NOT used here.
	 * That address is the public-facing IP reported to UPnP clients via SOAP
	 * and NAT-PMP, which may differ from the interface address (e.g. behind
	 * carrier NAT).  The VPP static mapping must use the actual interface IP
	 * because that is the address VPP sees in packet headers. */
	if (vpp_getifaddr(ifname, &wan_addr) < 0)
		return -1;
	inet_ntop(AF_INET, &wan_addr, wan_str, INET_ADDRSTRLEN);
	syslog(LOG_DEBUG, "vpp: resolved %s -> %s", ifname, wan_str);
	memcpy(ext_ip, &wan_addr.s_addr, 4);

	/* Parse internal address */
	if (!inet_aton(iaddr, &ia)) {
		syslog(LOG_ERR, "vpp: bad iaddr '%s'", iaddr);
		return -1;
	}
	memcpy(local_ip, &ia.s_addr, 4);

	make_tag(tag, desc, origin);

	if (send_static_mapping(true, local_ip, ext_ip,
	                        iport, eport, proto, tag) < 0)
		return -1;

	ts_add(eport, proto, timestamp);
	syslog(LOG_INFO, "vpp: added NAT44 mapping %s:%hu -> %s:%hu proto %d",
	       wan_str, eport, iaddr, iport, proto);
	return 0;
}

int
add_redirect_rule2(const char *ifname,
                   const char *rhost,
                   unsigned short eport,
                   const char *iaddr,
                   unsigned short iport,
                   int proto,
                   const char *desc,
                   unsigned int timestamp)
{
	enum tag_origin origin;

	UNUSED(rhost);

	/* UPnP always provides a description; NAT-PMP does not. */
	origin = (desc && desc[0]) ? TAG_ORIGIN_UPNP : TAG_ORIGIN_NATPMP;

	return add_mapping_internal(ifname, eport, iaddr, iport,
	                            proto, desc, timestamp, origin);
}

/* VPP handles DNAT + FORWARD accept in a single static mapping -- no-op. */
int
add_filter_rule2(const char *ifname, const char *rhost, const char *iaddr,
                 unsigned short eport, unsigned short iport,
                 int proto, const char *desc)
{
	UNUSED(ifname); UNUSED(rhost); UNUSED(iaddr);
	UNUSED(eport);  UNUSED(iport); UNUSED(proto); UNUSED(desc);
	return 0;
}

/* No separate filter rules in VPP -- no-op stubs required by upnpstun.c. */
int
delete_filter_rule(const char *ifname, unsigned short port, int proto)
{
	UNUSED(ifname); UNUSED(port); UNUSED(proto);
	return 0;
}

int
delete_redirect_and_filter_rules(unsigned short eport, int proto)
{
	struct dump_ctx d;
	const struct mapping_rec *found;
	uint8_t tag[64];
	uint8_t local_ip[4], ext_ip[4];
	unsigned short iport;
	unsigned int i;

	if (collect_mappings(&d) < 0)
		return -1;

	/* Find the matching entry to get the external IP */
	found = NULL;
	for (i = 0; i < d.count; i++) {
		if (d.recs[i].external_port == eport &&
		    (int)d.recs[i].protocol == proto) {
			found = &d.recs[i];
			break;
		}
	}

	if (!found) {
		dump_ctx_free(&d);
		syslog(LOG_WARNING,
		       "vpp: delete: no static mapping found for eport=%hu proto=%d",
		       eport, proto);
		return -1;
	}

	memcpy(tag,      found->tag,         64);
	memcpy(local_ip, found->local_ip,    4);
	memcpy(ext_ip,   found->external_ip, 4);
	iport = found->local_port;
	dump_ctx_free(&d);

	if (send_static_mapping(false, local_ip, ext_ip,
	                        iport, eport, proto, tag) < 0)
		return -1;

	ts_remove(eport, proto);
	return 0;
}

/* -----------------------------------------------------------------------
 * commonrdr.h -- query functions
 * -------------------------------------------------------------------- */

int
get_redirect_rule_count(const char *ifname)
{
	struct dump_ctx d;
	int n;
	UNUSED(ifname);
	if (collect_mappings(&d) < 0)
		return -1;
	n = (int)d.count;
	dump_ctx_free(&d);
	return n;
}

int
get_redirect_rule(const char *ifname,
                  unsigned short eport, int proto,
                  char *iaddr, int iaddrlen,
                  unsigned short *iport,
                  char *desc, int desclen,
                  char *rhost, int rhostlen,
                  unsigned int *timestamp,
                  u_int64_t *packets, u_int64_t *bytes)
{
	struct dump_ctx d;
	const struct mapping_rec *found;
	struct in_addr ia;
	unsigned int i;

	UNUSED(ifname);

	if (collect_mappings(&d) < 0)
		return -1;

	found = NULL;
	for (i = 0; i < d.count; i++) {
		if (d.recs[i].external_port == eport &&
		    (int)d.recs[i].protocol == proto) {
			found = &d.recs[i];
			break;
		}
	}

	if (!found) {
		dump_ctx_free(&d);
		return -1;
	}

	if (iaddr && iaddrlen > 0) {
		memcpy(&ia.s_addr, found->local_ip, 4);
		inet_ntop(AF_INET, &ia, iaddr, (socklen_t)iaddrlen);
	}
	if (iport)
		*iport = found->local_port;
	if (desc && desclen > 0)
		tag_to_desc(found->tag, desc, desclen);
	if (rhost && rhostlen > 0)
		rhost[0] = '\0';
	if (timestamp)
		*timestamp = ts_get(eport, proto);
	if (packets)
		*packets = 0;
	if (bytes)
		*bytes = 0;

	dump_ctx_free(&d);
	return 0;
}

int
get_redirect_rule_by_index(int index,
                           char *ifname,
                           unsigned short *eport,
                           char *iaddr, int iaddrlen,
                           unsigned short *iport,
                           int *proto,
                           char *desc, int desclen,
                           char *rhost, int rhostlen,
                           unsigned int *timestamp,
                           u_int64_t *packets, u_int64_t *bytes)
{
	struct dump_ctx d;
	const struct mapping_rec *m;
	struct in_addr ia;

	if (collect_mappings(&d) < 0)
		return -1;

	if (index < 0 || (unsigned int)index >= d.count) {
		dump_ctx_free(&d);
		return -1;
	}

	m = &d.recs[index];

	if (ifname)
		ifname[0] = '\0';
	if (eport)
		*eport = m->external_port;
	if (iaddr && iaddrlen > 0) {
		memcpy(&ia.s_addr, m->local_ip, 4);
		inet_ntop(AF_INET, &ia, iaddr, (socklen_t)iaddrlen);
	}
	if (iport)
		*iport = m->local_port;
	if (proto)
		*proto = (int)m->protocol;
	if (desc && desclen > 0)
		tag_to_desc(m->tag, desc, desclen);
	if (rhost && rhostlen > 0)
		rhost[0] = '\0';
	if (timestamp)
		*timestamp = ts_get(m->external_port, (int)m->protocol);
	if (packets)
		*packets = 0;
	if (bytes)
		*bytes = 0;

	dump_ctx_free(&d);
	return 0;
}

unsigned short *
get_portmappings_in_range(unsigned short startport, unsigned short endport,
                          int proto, unsigned int *number)
{
	struct dump_ctx d;
	unsigned short *arr;
	unsigned int n, i, j;

	*number = 0;

	if (collect_mappings(&d) < 0)
		return NULL;

	/* Count matching entries */
	n = 0;
	for (i = 0; i < d.count; i++) {
		if ((int)d.recs[i].protocol == proto &&
		    d.recs[i].external_port >= startport &&
		    d.recs[i].external_port <= endport)
			n++;
	}

	if (n == 0) {
		dump_ctx_free(&d);
		return NULL;
	}

	arr = malloc(n * sizeof(unsigned short));
	if (!arr) {
		dump_ctx_free(&d);
		return NULL;
	}

	j = 0;
	for (i = 0; i < d.count; i++) {
		if ((int)d.recs[i].protocol == proto &&
		    d.recs[i].external_port >= startport &&
		    d.recs[i].external_port <= endport)
			arr[j++] = d.recs[i].external_port;
	}

	dump_ctx_free(&d);
	*number = n;
	return arr;
}

/* -----------------------------------------------------------------------
 * commonrdr.h -- update functions
 * -------------------------------------------------------------------- */

int
update_portmapping(const char *ifname,
                   unsigned short eport, int proto,
                   unsigned short iport,
                   const char *desc,
                   unsigned int timestamp)
{
	struct dump_ctx d;
	const struct mapping_rec *found;
	uint8_t ext_ip[4], old_local_ip[4], old_tag[64], new_tag[64];
	unsigned short old_iport;
	unsigned int i;

	if (collect_mappings(&d) < 0)
		return -1;

	found = NULL;
	for (i = 0; i < d.count; i++) {
		if (d.recs[i].external_port == eport &&
		    (int)d.recs[i].protocol == proto) {
			found = &d.recs[i];
			break;
		}
	}
	if (!found) {
		dump_ctx_free(&d);
		return -1;
	}

	memcpy(ext_ip,      found->external_ip, 4);
	memcpy(old_local_ip, found->local_ip,   4);
	memcpy(old_tag,      found->tag,        64);
	old_iport = found->local_port;
	dump_ctx_free(&d);

	if (send_static_mapping(false, old_local_ip, ext_ip,
	                        old_iport, eport, proto, old_tag) < 0)
		return -1;

	make_tag(new_tag, desc, tag_get_origin(old_tag));

	if (send_static_mapping(true, old_local_ip, ext_ip,
	                        iport, eport, proto, new_tag) < 0)
		return -1;

	ts_add(eport, proto, timestamp);
	UNUSED(ifname);
	return 0;
}

int
update_portmapping_desc_timestamp(const char *ifname,
                                  unsigned short eport, int proto,
                                  const char *desc,
                                  unsigned int timestamp)
{
	struct dump_ctx d;
	const struct mapping_rec *found;
	uint8_t ext_ip[4], local_ip[4], old_tag[64], new_tag[64];
	unsigned short iport;
	unsigned int i;

	if (collect_mappings(&d) < 0)
		return -1;

	found = NULL;
	for (i = 0; i < d.count; i++) {
		if (d.recs[i].external_port == eport &&
		    (int)d.recs[i].protocol == proto) {
			found = &d.recs[i];
			break;
		}
	}
	if (!found) {
		dump_ctx_free(&d);
		return -1;
	}

	iport = found->local_port;
	memcpy(ext_ip,   found->external_ip, 4);
	memcpy(local_ip, found->local_ip,    4);
	memcpy(old_tag,  found->tag,         64);
	dump_ctx_free(&d);

	if (send_static_mapping(false, local_ip, ext_ip,
	                        iport, eport, proto, old_tag) < 0)
		return -1;

	make_tag(new_tag, desc, tag_get_origin(old_tag));

	if (send_static_mapping(true, local_ip, ext_ip,
	                        iport, eport, proto, new_tag) < 0)
		return -1;

	ts_add(eport, proto, timestamp);
	UNUSED(ifname);
	return 0;
}

/* ---------------------------------------------------------------------------
 * PCP PEER stubs for the VPP backend.
 *
 * VPP NAT44-ED does not maintain a separate "peer" mapping table distinct
 * from regular DNAT static mappings.  These stubs let the PCP server code
 * compile and link; runtime behaviour is:
 *
 *  - get_peer_rule_by_index   → always returns -1 (table appears empty;
 *                               lease-refresh loops terminate immediately).
 *  - add_peer_redirect_rule2  → installs a regular NAT44-ED static
 *                               mapping tagged with "pcp:<desc>".
 *                               The peer-address/rport is ignored at
 *                               the VPP level.
 *  - get_nat_ext_addr         → always returns 0 (conntrack-style lookup
 *                               not available in VPP NAT44-ED VAPI).
 * ---------------------------------------------------------------------------
 */

int
get_peer_rule_by_index(int index,
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
                       u_int64_t *bytes)
{
	(void)index; (void)ifname; (void)eport;
	(void)iaddr; (void)iaddrlen; (void)iport;
	(void)proto; (void)desc; (void)desclen;
	(void)rhost; (void)rhostlen; (void)rport;
	(void)timestamp; (void)packets; (void)bytes;
	return -1;
}

int
add_peer_redirect_rule2(const char *ifname,
                        const char *rhost, unsigned short rport,
                        const char *eaddr, unsigned short eport,
                        const char *iaddr, unsigned short iport,
                        int proto,
                        const char *desc, unsigned int timestamp)
{
	/* Ignore rhost/rport (peer address): VPP NAT44-ED static mappings are
	 * destination-only; store as a regular port-forward with PCP tag. */
	(void)rhost; (void)rport; (void)eaddr;
	return add_mapping_internal(ifname, eport, iaddr, iport,
	                            proto, desc, timestamp, TAG_ORIGIN_PCP);
}

int
get_nat_ext_addr(struct sockaddr *src, struct sockaddr *dst,
                 uint8_t proto, struct sockaddr *ret_ext)
{
	/* Conntrack-style "which external address/port would this flow use?"
	 * lookup is not available via VPP VAPI.  Return 0 (not found). */
	(void)src; (void)dst; (void)proto; (void)ret_ext;
	return 0;
}
