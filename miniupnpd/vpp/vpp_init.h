/* MiniUPnP project
 * VPP backend -- socket path and connection constants
 */
#ifndef VPP_INIT_H_INCLUDED
#define VPP_INIT_H_INCLUDED

/* Path to the VPP API Unix-domain socket.
 * Override at compile time: -DVPP_API_SOCK=\"/path/to/api.sock\" */
#ifndef VPP_API_SOCK
#define VPP_API_SOCK "/run/vpp/api.sock"
#endif

/* VAPI connection name reported to VPP (visible in "show api clients"). */
#define VPP_API_CLIENT_NAME "miniupnpd"

/* Timeout constants for the non-blocking dispatch loop.
 *
 * In VAPI_MODE_NONBLOCKING the typed wrappers (vapi_nat44_*()) only send the
 * request and return immediately.  The caller must pump
 * vapi_dispatch_one_timedwait() until the reply callback fires or the
 * deadline expires.  This prevents miniupnpd from hanging indefinitely if
 * VPP is unresponsive.
 *
 * VPP_VAPI_REQUEST_TIMEOUT_S -- overall per-request deadline (seconds).
 * VPP_VAPI_DISPATCH_SLICE_S  -- per-iteration wait slice; the loop re-checks
 *                               the deadline between slices.
 */
#ifndef VPP_VAPI_REQUEST_TIMEOUT_S
#define VPP_VAPI_REQUEST_TIMEOUT_S 5
#endif
#ifndef VPP_VAPI_DISPATCH_SLICE_S
#define VPP_VAPI_DISPATCH_SLICE_S  1
#endif

#endif /* VPP_INIT_H_INCLUDED */
