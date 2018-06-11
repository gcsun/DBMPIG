/*
 sun
*/
#ifndef __SECGW_H__
#define __SECGW_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_acl.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_cryptodev.h>
#include <rte_spinlock.h>

#include <rte_jobstats.h>
#include <rte_timer.h>
#include <rte_alarm.h>

#include "ipsec.h"
#include "parser.h"
#include "secgw.h"
#include "main.h"

/*
 * Configurable number of RX/TX ring descriptors
 */
#define IPSEC_SECGW_RX_DESC_DEFAULT 128
#define IPSEC_SECGW_TX_DESC_DEFAULT 512

#define RTE_LOGTYPE_IPSEC RTE_LOGTYPE_USER1

#define MAX_JUMBO_PKT_LEN 9600

#define MEMPOOL_CACHE_SIZE 256

#define OPTION_CONFIG "config"
#define OPTION_SINGLE_SA "single-sa"

#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

#define MAX_RX_QUEUE_PER_LCORE 16

#define MAX_LCORE_PARAMS 1024

#if RTE_BYTE_ORDER != RTE_LITTLE_ENDIAN
#define __BYTES_TO_UINT64(a, b, c, d, e, f, g, h) \
    (((uint64_t)((a)&0xff) << 56) |               \
     ((uint64_t)((b)&0xff) << 48) |               \
     ((uint64_t)((c)&0xff) << 40) |               \
     ((uint64_t)((d)&0xff) << 32) |               \
     ((uint64_t)((e)&0xff) << 24) |               \
     ((uint64_t)((f)&0xff) << 16) |               \
     ((uint64_t)((g)&0xff) << 8) |                \
     ((uint64_t)(h)&0xff))
#else
#define __BYTES_TO_UINT64(a, b, c, d, e, f, g, h) \
    (((uint64_t)((h)&0xff) << 56) |               \
     ((uint64_t)((g)&0xff) << 48) |               \
     ((uint64_t)((f)&0xff) << 40) |               \
     ((uint64_t)((e)&0xff) << 32) |               \
     ((uint64_t)((d)&0xff) << 24) |               \
     ((uint64_t)((c)&0xff) << 16) |               \
     ((uint64_t)((b)&0xff) << 8) |                \
     ((uint64_t)(a)&0xff))
#endif

#define ETHADDR(a, b, c, d, e, f) (__BYTES_TO_UINT64(a, b, c, d, e, f, 0, 0))

#define ETHADDR_TO_UINT64(addr) __BYTES_TO_UINT64( \
    addr.addr_bytes[0], addr.addr_bytes[1],        \
    addr.addr_bytes[2], addr.addr_bytes[3],        \
    addr.addr_bytes[4], addr.addr_bytes[5],        \
    0, 0)

/* port/source ethernet addr and destination ethernet addr */
struct ethaddr_info
{
    uint64_t src, dst;
};

struct ethaddr_info ethaddr_tbl[RTE_MAX_ETHPORTS] = {
    {0, ETHADDR(0x00, 0x16, 0x3e, 0x7e, 0x94, 0x9a)},
    {0, ETHADDR(0x00, 0x16, 0x3e, 0x22, 0xa1, 0xd9)},
    {0, ETHADDR(0x00, 0x16, 0x3e, 0x08, 0x69, 0x26)},
    {0, ETHADDR(0x00, 0x16, 0x3e, 0x49, 0x9e, 0xdd)}};

int32_t promiscuous_on = 1;
int32_t numa_on = 1; /**< NUMA is enabled by default. */
uint32_t nb_lcores;
uint32_t single_sa;
uint32_t single_sa_idx;
uint16_t nb_rxd = IPSEC_SECGW_RX_DESC_DEFAULT;
uint16_t nb_txd = IPSEC_SECGW_TX_DESC_DEFAULT;

struct lcore_rx_queue
{
    uint8_t port_id;
    uint8_t queue_id;
} __rte_cache_aligned;

struct lcore_params
{
    uint8_t port_id;
    uint8_t queue_id;
    uint8_t lcore_id;
} __rte_cache_aligned;

struct lcore_params lcore_params_array[MAX_LCORE_PARAMS];

struct lcore_params *lcore_params;
uint16_t nb_lcore_params;

struct rte_hash *cdev_map_in;
struct rte_hash *cdev_map_out;

struct buffer
{
    uint16_t len;
    struct rte_mbuf *m_table[MAX_PKT_BURST] __rte_aligned(sizeof(void *));
};

struct lcore_conf
{
    uint16_t nb_rx_queue;
    struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
    uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
    struct buffer tx_mbufs[RTE_MAX_ETHPORTS];
    struct ipsec_ctx inbound;
    struct ipsec_ctx outbound;
    struct rt_ctx *rt4_ctx;
    struct rt_ctx *rt6_ctx;
} __rte_cache_aligned;

struct lcore_conf lcore_conf[RTE_MAX_LCORE];

void prepare_tx_pkt(struct rte_mbuf *pkt, uint8_t port)
{
    struct ip *ip;
    struct ether_hdr *ethhdr;

    ip = rte_pktmbuf_mtod(pkt, struct ip *);

    ethhdr = (struct ether_hdr *)rte_pktmbuf_prepend(pkt, ETHER_HDR_LEN);

    if (ip->ip_v == IPVERSION)
    {
        pkt->ol_flags |= PKT_TX_IP_CKSUM | PKT_TX_IPV4;
        pkt->l3_len = sizeof(struct ip);
        pkt->l2_len = ETHER_HDR_LEN;

        ethhdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
    }
    else
    {
        pkt->ol_flags |= PKT_TX_IPV6;
        pkt->l3_len = sizeof(struct ip6_hdr);
        pkt->l2_len = ETHER_HDR_LEN;

        ethhdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv6);
    }

    memcpy(&ethhdr->s_addr, &ethaddr_tbl[port].src,
           sizeof(struct ether_addr));
    memcpy(&ethhdr->d_addr, &ethaddr_tbl[port].dst,
           sizeof(struct ether_addr));
}

void prepare_tx_burst(struct rte_mbuf *pkts[], uint16_t nb_pkts, uint8_t port)
{
    int32_t i;
    const int32_t prefetch_offset = 2;

    for (i = 0; i < (nb_pkts - prefetch_offset); i++)
    {
        rte_mbuf_prefetch_part2(pkts[i + prefetch_offset]);
        prepare_tx_pkt(pkts[i], port);
    }
    /* Process left packets */
    for (; i < nb_pkts; i++)
        prepare_tx_pkt(pkts[i], port);
}

/* Enqueue a single packet, and send burst if queue is filled */
int32_t
send_single_packet(struct rte_mbuf *m, uint8_t port)
{
    uint32_t lcore_id;
    uint32_t bsz_wr;
    uint16_t len;
    struct app_lcore_params_worker *lp;
    int ret;

    bsz_wr = app.burst_size_worker_write;

    lcore_id = rte_lcore_id();

    lp = &app.lcore_params[lcore_id].worker;
    len = lp->mbuf_out[port].n_mbufs;
    lp->mbuf_out[port].array[len++] = m;
    if (likely(len < bsz_wr))
    {
        lp->mbuf_out[port].n_mbufs = len;
        return 0;
    }

    //it is time to burst packet to ring_out
    ret = rte_ring_sp_enqueue_bulk(
        lp->rings_out[port],
        (void **)lp->mbuf_out[port].array,
        bsz_wr);

    if (unlikely(ret == -ENOBUFS))
    {
        uint32_t k;
        for (k = 0; k < bsz_wr; k++)
        {
            struct rte_mbuf *pkt_to_free = lp->mbuf_out[port].array[k];
            rte_pktmbuf_free(pkt_to_free);
        }
    }

    lp->mbuf_out[port].n_mbufs = 0;
    lp->mbuf_out_flush[port] = 0;

    return 1;
}

void inbound_sp_sa(struct sp_ctx *sp, struct sa_ctx *sa, struct traffic_type *ip,
                   uint16_t lim)
{
    struct rte_mbuf *m;
    uint32_t i, j, res, sa_idx;

    if (ip->num == 0 || sp == NULL)
        return;

    rte_acl_classify((struct rte_acl_ctx *)sp, ip->data, ip->res,
                     ip->num, DEFAULT_MAX_CATEGORIES);

    j = 0;
    for (i = 0; i < ip->num; i++)
    {
        m = ip->pkts[i];
        res = ip->res[i];
        if (res & BYPASS)
        {
            ip->pkts[j++] = m;
            continue;
        }
        if (res & DISCARD || i < lim)
        {
            rte_pktmbuf_free(m);
            continue;
        }
        /* Only check SPI match for processed IPSec packets */
        sa_idx = ip->res[i] & PROTECT_MASK;
        if (sa_idx == 0 || !inbound_sa_check(sa, m, sa_idx))
        {
            rte_pktmbuf_free(m);
            continue;
        }
        ip->pkts[j++] = m;
    }
    ip->num = j;
}

void outbound_sp(struct sp_ctx *sp, struct traffic_type *ip,
                 struct traffic_type *ipsec)
{
    struct rte_mbuf *m;
    uint32_t i, j, sa_idx;

    if (ip->num == 0 || sp == NULL)
        return;

    rte_acl_classify((struct rte_acl_ctx *)sp, ip->data, ip->res,
                     ip->num, DEFAULT_MAX_CATEGORIES);

    j = 0;
    for (i = 0; i < ip->num; i++)
    {
        m = ip->pkts[i];
        sa_idx = ip->res[i] & PROTECT_MASK;
        if ((ip->res[i] == 0) || (ip->res[i] & DISCARD))
            rte_pktmbuf_free(m);
        else if (sa_idx != 0)
        {
            //debug
            // printf("\nsa_idx = %d\n", sa_idx);

            ipsec->res[ipsec->num] = sa_idx;
            ipsec->pkts[ipsec->num++] = m;
        }
        else /* BYPASS */
            ip->pkts[j++] = m;
    }
    ip->num = j;
}

void route4_pkts(struct rt_ctx *rt_ctx, struct rte_mbuf *pkts[], uint8_t nb_pkts)
{
    uint32_t hop[MAX_PKT_BURST * 2];
    uint32_t dst_ip[MAX_PKT_BURST * 2];
    uint16_t i, offset;

    if (nb_pkts == 0)
        return;

    for (i = 0; i < nb_pkts; i++)
    {
        offset = offsetof(struct ip, ip_dst);
        dst_ip[i] = *rte_pktmbuf_mtod_offset(pkts[i],
                                             uint32_t *, offset);
        dst_ip[i] = rte_be_to_cpu_32(dst_ip[i]);
    }

    rte_lpm_lookup_bulk((struct rte_lpm *)rt_ctx, dst_ip, hop, nb_pkts);

    for (i = 0; i < nb_pkts; i++)
    {
        if ((hop[i] & RTE_LPM_LOOKUP_SUCCESS) == 0)
        {
            rte_pktmbuf_free(pkts[i]);
            continue;
        }
        send_single_packet(pkts[i], hop[i] & 0xff);
    }
}

void route6_pkts(struct rt_ctx *rt_ctx, struct rte_mbuf *pkts[], uint8_t nb_pkts)
{
    int16_t hop[MAX_PKT_BURST * 2];
    uint8_t dst_ip[MAX_PKT_BURST * 2][16];
    uint8_t *ip6_dst;
    uint16_t i, offset;

    if (nb_pkts == 0)
        return;

    for (i = 0; i < nb_pkts; i++)
    {
        offset = offsetof(struct ip6_hdr, ip6_dst);
        ip6_dst = rte_pktmbuf_mtod_offset(pkts[i], uint8_t *, offset);
        memcpy(&dst_ip[i][0], ip6_dst, 16);
    }

    rte_lpm6_lookup_bulk_func((struct rte_lpm6 *)rt_ctx, dst_ip,
                              hop, nb_pkts);

    for (i = 0; i < nb_pkts; i++)
    {
        if (hop[i] == -1)
        {
            rte_pktmbuf_free(pkts[i]);
            continue;
        }
        send_single_packet(pkts[i], hop[i] & 0xff);
    }
}

/* display usage */
void print_usage(const char *prgname)
{
    printf("%s [EAL options] -- -p PORTMASK -P -u PORTMASK"
           "  --" OPTION_CONFIG " (port,queue,lcore)[,(port,queue,lcore]"
           " --single-sa SAIDX -f CONFIG_FILE\n"
           "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
           "  -P : enable promiscuous mode\n"
           "  -u PORTMASK: hexadecimal bitmask of unprotected ports\n"
           "  --" OPTION_CONFIG ": (port,queue,lcore): "
           "rx queues configuration\n"
           "  --single-sa SAIDX: use single SA index for outbound, "
           "bypassing the SP\n"
           "  -f CONFIG_FILE: Configuration file path\n",
           prgname);
}

int32_t
parse_portmask(const char *portmask)
{
    char *end = NULL;
    unsigned long pm;

    /* parse hexadecimal string */
    pm = strtoul(portmask, &end, 16);
    if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if ((pm == 0) && errno)
        return -1;

    return pm;
}

int32_t
parse_decimal(const char *str)
{
    char *end = NULL;
    unsigned long num;

    num = strtoul(str, &end, 10);
    if ((str[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    return num;
}

void print_ethaddr(const char *name, const struct ether_addr *eth_addr)
{
    char buf[ETHER_ADDR_FMT_SIZE];
    ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
    printf("%s%s", name, buf);
}

#endif /* __SECGW_H__ */