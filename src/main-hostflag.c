/*

    Tracks per-host state during a scan so we can flag hosts whose
    response pattern looks like an IDS, tarpit, or port-spoofing
    middlebox and stop emitting per-port records for them.

    This is an asynchronous and "stateless" scanner. To detect
    middleboxes that lie on every port we must accumulate a small
    amount of cross-packet state per target host: how many opens we
    have seen, whether the TCP window is uniform across those opens,
    whether SYN-ACKs carry a tiny window or no TCP options, and how
    many dedup-driven retransmissions we have observed.

    The tiny-window and missing-options checks implement stage 1 of the
    degreaser methodology (Alt, Beverly, Dainotti, "Uncovering Network
    Tarpits with Degreaser", ACSAC'14). Stage 2 -- completing the
    handshake and probing with a window-sized data packet to separate
    netfilter TARPIT from LaBrea from a real small-window host --
    requires per-host TCP state and lives in the scan orchestrator,
    not in this stateless receive path.

    Memory is bounded: we use a fixed-size hash table mirroring the
    `main-dedup.c` pattern. Hash collisions silently overwrite the
    older slot; this is acceptable because flagged hosts strongly
    cluster and occasional false negatives on collision are cheap
    compared to unbounded allocation on the receive path.

    Signal vocabulary is deliberately generic ("tiny_window",
    "uniform_window", "no_tcp_options",
    "synack_retransmit") so the C fork carries no product-facing
    strings; downstream classifiers map signal combinations to
    product-level enum values.

    Note on IP TTL: an earlier revision tracked TTL uniformity. It was
    removed after lab testing showed every target returning two
    alternating TTL values one hop apart -- ECMP/multipath routing,
    not middlebox behaviour -- which cleared the uniformity bit on the
    second packet and made the signal fire on ~5% of genuinely uniform
    hosts. TTL is not stable enough over real internet paths to carry
    a fingerprint.
*/
#include "main-hostflag.h"
#include "util-malloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Number of slots in the hash table. Mirrors DEDUP_ENTRIES.
 */
#define HOSTFLAG_ENTRIES 65536

/**
 * Minimum open-port sample size required before the uniformity
 * signal (`uniform_window`) may fire.
 *
 * The TCP window advertised in a SYN-ACK is set by the responder's kernel,
 * not by the listening application, so every port on a single host shares
 * one window value whether or not the ports are real. Uniformity therefore
 * proves only "one TCP stack answered", which is true of any ordinary
 * server -- a floor of 10 flagged legitimate customer hosts at ~100% in
 * testing.
 *
 * 100 is a sample size large enough that a flat window AND a flat TTL
 * across every response is implausible for a host running a genuine mix of
 * services, while staying below the point where rate-limited middleboxes
 * stop responding. A 600 floor missed real appliances that throttled to
 * 111-280 observed ports under load, making detection depend on scan rate.
 *
 * This floor is independent of `--flag-hosts-after`: that flag expresses
 * "implausibly many open ports", which is a product-level risk concern, not
 * a middlebox fingerprint; the open-port count plays no part in
 * detection at all.
 */
#define HOSTFLAG_UNIFORM_MIN_OPENS 100

/**
 * Number of dedup-driven duplicate SYN-ACKs on a single tuple
 * required to fire `synack_retransmit`.
 */
#define HOSTFLAG_RETRANSMIT_THRESHOLD 5

/**
 * State common to IPv4 and IPv6 entries. The IP-specific keys
 * (v4 uint or v6 128-bit) live on the outer entry types.
 */
struct HostFlagState
{
    unsigned open_count;
    unsigned first_window;
    unsigned short retransmit_count;
    unsigned short tiny_window_count;
    unsigned short no_options_count;
    unsigned char is_used:1;
    unsigned char is_flagged:1;
    unsigned char window_is_uniform:1;
};

struct HostFlagEntry_IPv4
{
    unsigned ip_them;
    struct HostFlagState s;
};

struct HostFlagEntry_IPv6
{
    ipv6address ip_them;
    struct HostFlagState s;
};

struct HostFlagTable
{
    unsigned tiny_window_threshold;
    struct HostFlagEntry_IPv4 entries[HOSTFLAG_ENTRIES];
    struct HostFlagEntry_IPv6 entries6[HOSTFLAG_ENTRIES];
};

/**
 * FNv1a helpers, mirroring main-dedup.c.
 */
static const unsigned hostflag_fnv1a_seed = 0x811C9DC5;

static inline unsigned hostflag_fnv1a(unsigned char c, unsigned hash)
{
    return (c ^ hash) * 0x01000193u;
}

static inline unsigned hostflag_fnv1a_longlong(unsigned long long data, unsigned hash)
{
    const unsigned char *buf = (const unsigned char *)&data;
    size_t i;
    for (i = 0; i < 8; i++)
        hash = hostflag_fnv1a(buf[i], hash);
    return hash;
}

static inline unsigned hostflag_hash_ipv4(unsigned ip)
{
    unsigned hash = (ip * 0x01000193u) ^ (ip >> 16) ^ (ip >> 24);
    return hash & (HOSTFLAG_ENTRIES - 1);
}

static inline unsigned hostflag_hash_ipv6(ipv6address ip)
{
    unsigned hash = hostflag_fnv1a_seed;
    hash = hostflag_fnv1a_longlong(ip.hi, hash);
    hash = hostflag_fnv1a_longlong(ip.lo, hash);
    return hash & (HOSTFLAG_ENTRIES - 1);
}

/**
 * Does this SYN-ACK carry at least one meaningful TCP option?
 *
 * Walks the option area between the fixed 20-byte TCP header and the end
 * of the header as given by the data-offset field. Returns non-zero on the
 * first option of kind >= 2.
 *
 * EOL (kind 0) and NOP (kind 1) are padding and deliberately do NOT count:
 * a bare SYN-ACK padded to a 4-byte boundary carries no information about
 * the responder, so counting padding would make a synthesised packet look
 * like a real host. Degreaser's get_tcp_option_count() counts them but
 * assigns them no option flag, which has the same effect in its
 * `options != SCAN_OPT_MSS` comparison.
 *
 *   px               - the whole captured frame
 *   length           - captured frame length
 *   transport_offset - offset of the TCP header within the frame
 */
unsigned
hostflag_synack_has_tcp_options(const unsigned char *px, unsigned length,
                                unsigned transport_offset)
{
    unsigned hdr_len;
    unsigned offset;
    unsigned max;

    /* Need at least the fixed 20-byte TCP header to read the data offset. */
    if (px == NULL || transport_offset + 20 > length)
        return 0;

    /* Data offset lives in the high nibble of byte 12, in 32-bit words. */
    hdr_len = (px[transport_offset + 12] >> 4) * 4;

    /* No option area, or a nonsensical/truncated header. */
    if (hdr_len <= 20)
        return 0;

    max = transport_offset + hdr_len;
    if (max > length)
        max = length;

    offset = transport_offset + 20;
    while (offset < max) {
        unsigned kind = px[offset++];

        if (kind == 0x00)       /* EOL: stop, per spec */
            break;
        if (kind == 0x01)       /* NOP: padding, 1 byte, no length field */
            continue;

        /* Any other kind is a real option. */
        return 1;
    }
    return 0;
}

/**
 * Update per-host state and compute the signal bitmask. This is the
 * IP-agnostic core; callers wrap it with the slot-lookup and
 * collision-reset logic for their address family.
 */
static unsigned
hostflag_update_state(struct HostFlagState *s,
                      unsigned tiny_window_threshold,
                      unsigned tcp_window,
                      unsigned has_tcp_options,
                      unsigned is_synack_retransmit)
{
    unsigned signals = 0;

    /* Step 1: retransmit accounting. Cap the counter to avoid wrap. */
    if (is_synack_retransmit) {
        if (s->retransmit_count < 0xFFFF)
            s->retransmit_count++;
        if (s->retransmit_count == HOSTFLAG_RETRANSMIT_THRESHOLD)
            signals |= HOSTFLAG_SIGNAL_SYNACK_RETRANSMIT;
    }

    /* Step 2: if already flagged, drop any accumulated signal. */
    if (s->is_flagged)
        return 0;

    /* Step 3 vs Step 5: initialize on first observation, else
     * increment and reconcile uniformity bits. */
    if (!s->is_used) {
        s->is_used = 1;
        s->first_window = tcp_window;
        s->window_is_uniform = 1;
        s->open_count = 1;
    } else {
        if (s->open_count < 0xFFFFFFFFu)
            s->open_count++;
        if (tcp_window != s->first_window)
            s->window_is_uniform = 0;
    }

    /* Step 4: tiny_window fires once `tiny_window_threshold` SYN-ACKs
     * with window <= HOSTFLAG_TINY_WINDOW_MAX have accumulated.
     *
     * An earlier revision tested `window == 0` exactly, following the LZR
     * paper's zero-window finding. Lab testing against known tarpits
     * showed that to be wrong in practice: netfilter TARPIT answers
     * win=5 and LaBrea win=10, so both escaped detection while only a
     * synproxy (win=0) matched. Degreaser's threshold of 20 covers all
     * three and still sits far below any kernel-chosen window. */
    if (tcp_window <= HOSTFLAG_TINY_WINDOW_MAX) {
        if (s->tiny_window_count < 0xFFFF)
            s->tiny_window_count++;
        if (s->tiny_window_count >= tiny_window_threshold)
            signals |= HOSTFLAG_SIGNAL_TINY_WINDOW;
    }

    /* Step 4b: no_tcp_options fires on the same threshold. Degreaser
     * treats the presence of TCP options in a SYN-ACK as its primary
     * real-host discriminator, checked before the window: a real kernel
     * echoes MSS and typically window-scale and SACK-permitted, whereas
     * a tarpit or port-spoofer synthesises a bare SYN-ACK. Expressed
     * here as the absence being the signal, so the bitmask stays
     * "evidence of a middlebox". */
    if (!has_tcp_options) {
        if (s->no_options_count < 0xFFFF)
            s->no_options_count++;
        if (s->no_options_count >= tiny_window_threshold)
            signals |= HOSTFLAG_SIGNAL_NO_TCP_OPTIONS;
    }

    /* Step 5: uniformity, gated only on its own minimum sample size.
     *
     * There is deliberately no open-port threshold anywhere in this
     * function. An earlier design gated detection on `--flag-hosts-after`
     * and reported a `high_port_count` signal alongside whatever fired.
     * Both were removed: a host legitimately running many applications
     * behind one server holds hundreds of open ports, so the count is not
     * evidence of a middlebox -- that concern belongs to product-level
     * excessive-port risk and mass-vhosting detection. Gating on it also
     * made detection depend on scan rate, because a middlebox that
     * rate-limits under load may never reach a high count. */
    if (s->open_count >= HOSTFLAG_UNIFORM_MIN_OPENS) {
        if (s->window_is_uniform)
            signals |= HOSTFLAG_SIGNAL_UNIFORM_WINDOW;
    }

    /* Step 6: transition to FLAGGED if any fingerprint fired. */
    if (signals != 0)
        s->is_flagged = 1;
    return signals;
}

struct HostFlagTable *
hostflag_create(unsigned tiny_window_threshold)
{
    struct HostFlagTable *table;
    if (tiny_window_threshold == 0)
        tiny_window_threshold = HOSTFLAG_DEFAULT_TINY_WINDOW_THRESHOLD;
    table = CALLOC(1, sizeof(*table));
    table->tiny_window_threshold = tiny_window_threshold;
    return table;
}

void
hostflag_destroy(struct HostFlagTable *table)
{
    if (table == NULL)
        return;
    free(table);
}

unsigned
hostflag_observe(struct HostFlagTable *table,
                 ipaddress ip_them,
                 unsigned tcp_window,
                 unsigned has_tcp_options,
                 unsigned is_synack_retransmit)
{
    if (table == NULL)
        return 0;

    if (ip_them.version == 6) {
        unsigned hash = hostflag_hash_ipv6(ip_them.ipv6);
        struct HostFlagEntry_IPv6 *e = &table->entries6[hash];
        int same = (e->s.is_used
                    && e->ip_them.hi == ip_them.ipv6.hi
                    && e->ip_them.lo == ip_them.ipv6.lo);
        if (!same) {
            memset(e, 0, sizeof(*e));
            e->ip_them = ip_them.ipv6;
        }
        return hostflag_update_state(&e->s,
                                     table->tiny_window_threshold,
                                     tcp_window, has_tcp_options,
                                     is_synack_retransmit);
    } else {
        unsigned hash = hostflag_hash_ipv4(ip_them.ipv4);
        struct HostFlagEntry_IPv4 *e = &table->entries[hash];
        int same = (e->s.is_used && e->ip_them == ip_them.ipv4);
        if (!same) {
            memset(e, 0, sizeof(*e));
            e->ip_them = ip_them.ipv4;
        }
        return hostflag_update_state(&e->s,
                                     table->tiny_window_threshold,
                                     tcp_window, has_tcp_options,
                                     is_synack_retransmit);
    }
}

unsigned
hostflag_is_flagged(struct HostFlagTable *table, ipaddress ip_them)
{
    if (table == NULL)
        return 0;
    if (ip_them.version == 6) {
        unsigned hash = hostflag_hash_ipv6(ip_them.ipv6);
        struct HostFlagEntry_IPv6 *e = &table->entries6[hash];
        return e->s.is_used
            && e->ip_them.hi == ip_them.ipv6.hi
            && e->ip_them.lo == ip_them.ipv6.lo
            && e->s.is_flagged;
    } else {
        unsigned hash = hostflag_hash_ipv4(ip_them.ipv4);
        struct HostFlagEntry_IPv4 *e = &table->entries[hash];
        return e->s.is_used
            && e->ip_them == ip_them.ipv4
            && e->s.is_flagged;
    }
}

/**
 * Render a signal bitmask as a comma-separated string. Names are
 * emitted in a fixed order so downstream diffs are meaningful.
 */
size_t
hostflag_signals_to_string(unsigned signals, char *buf, size_t buf_size)
{
    static const struct {
        unsigned    bit;
        const char *name;
    } table[] = {
        { HOSTFLAG_SIGNAL_TINY_WINDOW,       "tiny_window"       },
        { HOSTFLAG_SIGNAL_UNIFORM_WINDOW,    "uniform_window"    },
        { HOSTFLAG_SIGNAL_NO_TCP_OPTIONS,    "no_tcp_options"    },
        { HOSTFLAG_SIGNAL_SYNACK_RETRANSMIT, "synack_retransmit" }
    };
    const size_t n = sizeof(table) / sizeof(table[0]);
    size_t written = 0;
    int need_comma = 0;
    size_t i;

    if (buf == NULL || buf_size == 0)
        return 0;
    buf[0] = '\0';

    for (i = 0; i < n; i++) {
        size_t name_len, need;
        if ((signals & table[i].bit) == 0)
            continue;
        name_len = strlen(table[i].name);
        need = name_len + (need_comma ? 1 : 0);
        if (written + need >= buf_size)
            break;
        if (need_comma)
            buf[written++] = ',';
        memcpy(buf + written, table[i].name, name_len);
        written += name_len;
        need_comma = 1;
    }
    buf[written] = '\0';
    return written;
}

/**
 * Self-test. Mirrors dedup_selftest style: capture `line` on any
 * failure and report file+line.
 */
int
hostflag_selftest(void)
{
    struct HostFlagTable *table = NULL;
    unsigned line = 0;
    ipaddress ip;
    unsigned r;
    unsigned i;
    char buf[128];
    size_t n;

    ip.version = 4;

    /* Throughout: the 4th hostflag_observe() arg is has_tcp_options.
     * 1 = SYN-ACK carried a real TCP option (real-host-like),
     * 0 = bare SYN-ACK (middlebox-like). A large window plus options is
     * the "ordinary server" shape and must never flag. */

    /* Test 1: an ordinary server -- large varied windows, options present,
     * well past every threshold -- must never be flagged. */
    table = hostflag_create(HOSTFLAG_DEFAULT_TINY_WINDOW_THRESHOLD);
    if (table == NULL) { line = __LINE__; goto fail; }
    ip.ipv4 = 0x01020304;
    for (i = 0; i < HOSTFLAG_UNIFORM_MIN_OPENS + 50; i++) {
        r = hostflag_observe(table, ip, 1024 + (i % 97), 1, 0);
        if (r != 0) { line = __LINE__; goto fail; }
    }
    if (hostflag_is_flagged(table, ip)) { line = __LINE__; goto fail; }
    hostflag_destroy(table); table = NULL;

    /* Test 2: uniform window with options present does NOT fire below the
     * uniformity floor, then fires on reaching it. */
    table = hostflag_create(HOSTFLAG_DEFAULT_TINY_WINDOW_THRESHOLD);
    if (table == NULL) { line = __LINE__; goto fail; }
    ip.ipv4 = 0x05060708;
    for (i = 0; i < HOSTFLAG_UNIFORM_MIN_OPENS - 1; i++) {
        r = hostflag_observe(table, ip, 64240, 1, 0);
        if (r != 0) { line = __LINE__; goto fail; }
    }
    if (hostflag_is_flagged(table, ip)) { line = __LINE__; goto fail; }
    r = hostflag_observe(table, ip, 64240, 1, 0);
    if ((r & HOSTFLAG_SIGNAL_UNIFORM_WINDOW) == 0)   { line = __LINE__; goto fail; }
    if (r & HOSTFLAG_SIGNAL_TINY_WINDOW)             { line = __LINE__; goto fail; }
    if (r & HOSTFLAG_SIGNAL_NO_TCP_OPTIONS)          { line = __LINE__; goto fail; }
    if (!hostflag_is_flagged(table, ip))             { line = __LINE__; goto fail; }
    r = hostflag_observe(table, ip, 64240, 1, 0);
    if (r != 0) { line = __LINE__; goto fail; }
    hostflag_destroy(table); table = NULL;

    /* Test 2b: uniformity depends only on the open-port count reaching the
     * uniformity floor -- there is no separate open-port threshold to
     * satisfy, and no high_port_count signal to report. */
    table = hostflag_create(HOSTFLAG_DEFAULT_TINY_WINDOW_THRESHOLD);
    if (table == NULL) { line = __LINE__; goto fail; }
    ip.ipv4 = 0x05060709;
    for (i = 0; i < HOSTFLAG_UNIFORM_MIN_OPENS - 1; i++) {
        r = hostflag_observe(table, ip, 64240, 1, 0);
        if (r != 0) { line = __LINE__; goto fail; }
    }
    r = hostflag_observe(table, ip, 64240, 1, 0);
    if ((r & HOSTFLAG_SIGNAL_UNIFORM_WINDOW) == 0)  { line = __LINE__; goto fail; }
    if (!hostflag_is_flagged(table, ip))            { line = __LINE__; goto fail; }
    hostflag_destroy(table); table = NULL;

    /* Test 3a: tiny_window does NOT fire below the threshold, and fires on
     * the Nth tiny-window observation. Uses win=5 (netfilter TARPIT) with
     * options present, so tiny_window is isolated from no_tcp_options. */
    table = hostflag_create(3);
    if (table == NULL) { line = __LINE__; goto fail; }
    ip.ipv4 = 0x0a0b0c0d;
    for (i = 0; i < 2; i++) {
        r = hostflag_observe(table, ip, 5, 1, 0);
        if (r & HOSTFLAG_SIGNAL_TINY_WINDOW) { line = __LINE__; goto fail; }
    }
    if (hostflag_is_flagged(table, ip)) { line = __LINE__; goto fail; }
    r = hostflag_observe(table, ip, 5, 1, 0);
    if ((r & HOSTFLAG_SIGNAL_TINY_WINDOW) == 0) { line = __LINE__; goto fail; }
    if (!hostflag_is_flagged(table, ip))        { line = __LINE__; goto fail; }
    hostflag_destroy(table); table = NULL;

    /* Test 3b: the degreaser boundary. win == HOSTFLAG_TINY_WINDOW_MAX is
     * tiny; one above it is not. LaBrea (10) and synproxy (0) are inside. */
    table = hostflag_create(1);
    if (table == NULL) { line = __LINE__; goto fail; }
    ip.ipv4 = 0x0a0b0c0e;
    r = hostflag_observe(table, ip, HOSTFLAG_TINY_WINDOW_MAX, 1, 0);
    if ((r & HOSTFLAG_SIGNAL_TINY_WINDOW) == 0) { line = __LINE__; goto fail; }
    hostflag_destroy(table); table = NULL;

    table = hostflag_create(1);
    if (table == NULL) { line = __LINE__; goto fail; }
    ip.ipv4 = 0x0a0b0c1e;
    r = hostflag_observe(table, ip, HOSTFLAG_TINY_WINDOW_MAX + 1, 1, 0);
    if (r & HOSTFLAG_SIGNAL_TINY_WINDOW) { line = __LINE__; goto fail; }
    if (hostflag_is_flagged(table, ip))  { line = __LINE__; goto fail; }
    hostflag_destroy(table); table = NULL;

    /* Test 3c: window 0 (synproxy) is tiny. */
    table = hostflag_create(1);
    if (table == NULL) { line = __LINE__; goto fail; }
    ip.ipv4 = 0x0a0b0c2e;
    r = hostflag_observe(table, ip, 0, 1, 0);
    if ((r & HOSTFLAG_SIGNAL_TINY_WINDOW) == 0) { line = __LINE__; goto fail; }
    hostflag_destroy(table); table = NULL;

    /* Test 3d: tiny_window_threshold==0 falls back to the default. */
    table = hostflag_create(0);
    if (table == NULL) { line = __LINE__; goto fail; }
    ip.ipv4 = 0x0a0b0c0f;
    for (i = 0; i < HOSTFLAG_DEFAULT_TINY_WINDOW_THRESHOLD - 1; i++) {
        r = hostflag_observe(table, ip, 10, 1, 0);
        if (r & HOSTFLAG_SIGNAL_TINY_WINDOW) { line = __LINE__; goto fail; }
    }
    r = hostflag_observe(table, ip, 10, 1, 0);
    if ((r & HOSTFLAG_SIGNAL_TINY_WINDOW) == 0) { line = __LINE__; goto fail; }
    hostflag_destroy(table); table = NULL;

    /* Test 3e: no_tcp_options fires on its own threshold, with a large
     * window so tiny_window cannot fire. This is the portspoof shape:
     * a normal-looking window but a synthesised, bare SYN-ACK. */
    table = hostflag_create(3);
    if (table == NULL) { line = __LINE__; goto fail; }
    ip.ipv4 = 0x0a0b0d01;
    for (i = 0; i < 2; i++) {
        r = hostflag_observe(table, ip, 64240, 0, 0);
        if (r & HOSTFLAG_SIGNAL_NO_TCP_OPTIONS) { line = __LINE__; goto fail; }
    }
    r = hostflag_observe(table, ip, 64240, 0, 0);
    if ((r & HOSTFLAG_SIGNAL_NO_TCP_OPTIONS) == 0) { line = __LINE__; goto fail; }
    if (r & HOSTFLAG_SIGNAL_TINY_WINDOW)           { line = __LINE__; goto fail; }
    hostflag_destroy(table); table = NULL;

    /* Test 3f: the tarpit shape -- tiny window AND no options together. */
    table = hostflag_create(2);
    if (table == NULL) { line = __LINE__; goto fail; }
    ip.ipv4 = 0x0a0b0d02;
    r = hostflag_observe(table, ip, 5, 0, 0);
    if (r != 0) { line = __LINE__; goto fail; }
    r = hostflag_observe(table, ip, 5, 0, 0);
    if ((r & HOSTFLAG_SIGNAL_TINY_WINDOW) == 0)    { line = __LINE__; goto fail; }
    if ((r & HOSTFLAG_SIGNAL_NO_TCP_OPTIONS) == 0) { line = __LINE__; goto fail; }
    hostflag_destroy(table); table = NULL;

    /* Test 4: a high open-port count alone must NOT flag a host. Varied
     * windows, options present -- the legitimate many-apps-one-server
     * case, well past any historical threshold. */
    table = hostflag_create(HOSTFLAG_DEFAULT_TINY_WINDOW_THRESHOLD);
    if (table == NULL) { line = __LINE__; goto fail; }
    ip.ipv4 = 0x11223344;
    for (i = 0; i < 200; i++) {
        r = hostflag_observe(table, ip, 1024 + (i % 89), 1, 0);
        if (r != 0) { line = __LINE__; goto fail; }
    }
    if (hostflag_is_flagged(table, ip)) { line = __LINE__; goto fail; }
    hostflag_destroy(table); table = NULL;

    /* Test 5: synack_retransmit fires at the 5th duplicate. */
    table = hostflag_create(HOSTFLAG_DEFAULT_TINY_WINDOW_THRESHOLD);
    if (table == NULL) { line = __LINE__; goto fail; }
    ip.ipv4 = 0x22334455;
    for (i = 0; i < 4; i++) {
        r = hostflag_observe(table, ip, 1024 + i, 1, 1);
        if (r != 0) { line = __LINE__; goto fail; }
    }
    r = hostflag_observe(table, ip, 9999, 1, 1);
    if ((r & HOSTFLAG_SIGNAL_SYNACK_RETRANSMIT) == 0) { line = __LINE__; goto fail; }
    if (!hostflag_is_flagged(table, ip))              { line = __LINE__; goto fail; }
    hostflag_destroy(table); table = NULL;

    /* Test 6: stable ordering of hostflag_signals_to_string. */
    n = hostflag_signals_to_string(
            HOSTFLAG_SIGNAL_SYNACK_RETRANSMIT
          | HOSTFLAG_SIGNAL_TINY_WINDOW
          | HOSTFLAG_SIGNAL_NO_TCP_OPTIONS,
            buf, sizeof(buf));
    if (n == 0) { line = __LINE__; goto fail; }
    if (strcmp(buf, "tiny_window,no_tcp_options,synack_retransmit") != 0) {
        line = __LINE__; goto fail;
    }
    n = hostflag_signals_to_string(HOSTFLAG_SIGNAL_NONE, buf, sizeof(buf));
    if (n != 0)         { line = __LINE__; goto fail; }
    if (buf[0] != '\0') { line = __LINE__; goto fail; }

    /* Test 7: NULL-table paths are safe, and create() always succeeds now
     * that there is no disabling threshold -- a 0 tiny-window threshold
     * selects the default rather than disabling the feature. Enablement is
     * decided by --detect-ips in main.c, not here. */
    hostflag_destroy(NULL);
    {
        struct HostFlagTable *t0 = hostflag_create(0);
        if (t0 == NULL) { line = __LINE__; goto fail; }
        hostflag_destroy(t0);
    }
    ip.ipv4 = 0x0;
    if (hostflag_observe(NULL, ip, 0, 0, 0) != 0) { line = __LINE__; goto fail; }
    if (hostflag_is_flagged(NULL, ip) != 0)       { line = __LINE__; goto fail; }

    return 0;

fail:
    if (table != NULL)
        hostflag_destroy(table);
    fprintf(stderr, "[-] selftest: 'hostflag' failed, file=%s, line=%u\n",
            __FILE__, line);
    return 1;
}
