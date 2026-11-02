#ifndef MAIN_HOSTFLAG_H
#define MAIN_HOSTFLAG_H
#include "massip-addr.h"
#include <stddef.h>

/* Signal bitmask values returned by hostflag_observe(). */
#define HOSTFLAG_SIGNAL_NONE              0x00
#define HOSTFLAG_SIGNAL_TINY_WINDOW       0x01
#define HOSTFLAG_SIGNAL_UNIFORM_WINDOW    0x02
#define HOSTFLAG_SIGNAL_NO_TCP_OPTIONS    0x04
#define HOSTFLAG_SIGNAL_SYNACK_RETRANSMIT 0x10

/* Default for --tiny-window-threshold when the user does not set it:
 * how many tiny-window SYN-ACKs must accumulate before the signal fires. */
#define HOSTFLAG_DEFAULT_TINY_WINDOW_THRESHOLD 5

/* A SYN-ACK advertising a window at or below this is "tiny". Sourced from
 * degreaser (Alt, Beverly, Dainotti, ACSAC'14), whose win_threshold
 * default is 20: netfilter TARPIT answers win=5, LaBrea win=10, and
 * synproxy win=0, while a real service advertises a kernel-chosen window
 * orders of magnitude larger. */
#define HOSTFLAG_TINY_WINDOW_MAX 20

struct HostFlagTable;

/* Create a new host-state hash table.
 *
 *   tiny_window_threshold - number of observations from a single host
 *                          required before `tiny_window` or
 *                          `no_tcp_options` fires. 0 selects
 *                          HOSTFLAG_DEFAULT_TINY_WINDOW_THRESHOLD. */
struct HostFlagTable *
hostflag_create(unsigned tiny_window_threshold);

void
hostflag_destroy(struct HostFlagTable *table);

/* Observe an incoming SYN-ACK for a host. Updates per-host state and
 * returns a bitmask of signals that fired on THIS observation (i.e.,
 * signals that transitioned the host to FLAGGED). Returns 0 if the
 * host was already flagged (caller should suppress output) OR if no
 * signals fired.
 *
 * The caller can distinguish "already flagged" from "not yet flagged"
 * with hostflag_is_flagged() below, called BEFORE observe.
 *
 * Parameters:
 *   tcp_window          - the SYN-ACK's TCP window size (0..65535)
 *   has_tcp_options     - non-zero if the SYN-ACK carried at least one
 *                         meaningful TCP option (kind >= 2; EOL and NOP
 *                         padding do not count). Degreaser treats the
 *                         presence of options as the primary real-host
 *                         discriminator: tarpits and spoofers synthesise
 *                         bare SYN-ACKs, while a real kernel echoes MSS
 *                         and usually window-scale/SACK.
 *   is_synack_retransmit - non-zero if the dedup module reports this
 *                         (host,port) tuple as a duplicate
 */
unsigned
hostflag_observe(struct HostFlagTable *table,
                 ipaddress ip_them,
                 unsigned tcp_window,
                 unsigned has_tcp_options,
                 unsigned is_synack_retransmit);

/* Does this SYN-ACK carry at least one meaningful TCP option (kind >= 2)?
 * EOL/NOP padding does not count. See the implementation for why. */
unsigned
hostflag_synack_has_tcp_options(const unsigned char *px, unsigned length,
                                unsigned transport_offset);

/* Returns non-zero if the host is already in the FLAGGED terminal state. */
unsigned
hostflag_is_flagged(struct HostFlagTable *table, ipaddress ip_them);

/* Convert a signal bitmask to a comma-separated string of packet-level
 * signal names. Writes at most `buf_size-1` bytes plus a null terminator
 * into `buf`. Returns the number of bytes written (excluding the null).
 * If no signals are set, writes an empty string. */
size_t
hostflag_signals_to_string(unsigned signals, char *buf, size_t buf_size);

/* Self-test. Returns 0 on success. */
int
hostflag_selftest(void);

#endif
