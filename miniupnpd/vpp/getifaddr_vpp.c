/* MiniUPnP project
 * VPP backend -- getifaddr() override
 *
 * When ext_ifname is a VPP-native interface (e.g. GigabitEthernet0/0/0),
 * the kernel ioctl(SIOCGIFADDR) path fails because the device only exists
 * inside VPP.  This file provides a getifaddr() that queries VPP via VAPI
 * for the external interface and falls through to the kernel for LAN
 * interfaces (which are Linux TAP/LCP pairs).
 *
 * We #include the original getifaddr.c but rename its getifaddr() to
 * getifaddr_kernel() so we can wrap it with VPP fallback logic.  This
 * keeps addr_is_reserved(), find_ipv6_addr(), and getifaddr_in6() from
 * the original file without duplication.
 *
 * Linked instead of getifaddr.o when building with --firewall=vpp.
 */

/* Rename the kernel implementation so we can wrap it. */
#define getifaddr getifaddr_kernel
#include "../getifaddr.c"
#undef getifaddr

#include <string.h>
#include <arpa/inet.h>

#include "../upnpglobalvars.h"

/* Provided by vpp_nat.c -- resolve an IPv4 address from VPP's interface
 * database.  Returns 0 on success, -1 on failure. */
extern int vpp_getifaddr(const char *ifname, struct in_addr *addr);

/* -------------------------------------------------------------------
 * VPP-aware getifaddr()
 *
 * Try VPP first for the external interface (avoids a failing ioctl +
 * syslog noise on every call).  Fall through to the kernel path for
 * LAN interfaces and when VPP is not yet connected.
 * ---------------------------------------------------------------- */
int
getifaddr(const char *ifname, char *buf, int len,
          struct in_addr *addr, struct in_addr *mask)
{
	/* If this is the WAN interface, try VPP first. */
	if (ext_if_name && strcmp(ifname, ext_if_name) == 0) {
		struct in_addr vpp_addr;
		if (vpp_getifaddr(ifname, &vpp_addr) == 0) {
			if (addr)
				*addr = vpp_addr;
			if (buf)
				inet_ntop(AF_INET, &vpp_addr, buf,
				          (socklen_t)len);
			if (mask)
				mask->s_addr = 0; /* mask not available from VPP */
			return GETIFADDR_OK;
		}
		/* VPP failed (not connected yet or interface not ready).
		 * Fall through to kernel -- the LCP mirror might exist. */
	}

	return getifaddr_kernel(ifname, buf, len, addr, mask);
}
