/*
 sun
*/

#include <rte_mbuf.h>

#include "ipsec.h"

#define NB_SOCKETS 4

#define NB_MBUF (32000)

#define CDEV_QUEUE_DESC 2048
#define CDEV_MAP_ENTRIES 1024
#define CDEV_MP_NB_OBJS 2048
#define CDEV_MP_CACHE_SZ 64
#define MAX_QUEUE_PAIRS 1

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET 3

/*--------------*/
/* mask of enabled ports */
uint32_t enabled_port_mask;
uint32_t unprotected_port_mask;
#define UNPROTECTED_PORT(port) (unprotected_port_mask & (1 << portid))

struct socket_ctx socket_ctx[NB_SOCKETS];

struct traffic_type
{
    const uint8_t *data[MAX_PKT_BURST * 2];
    struct rte_mbuf *pkts[MAX_PKT_BURST * 2];
    uint32_t res[MAX_PKT_BURST * 2];
    uint32_t num;
};

struct ipsec_traffic
{
    struct traffic_type ipsec;
    struct traffic_type ip4;
    struct traffic_type ip6;
    uint32_t pkts_num;
};

/*----*/

void prepare_tx_pkt(struct rte_mbuf *pkt, uint8_t port);

void prepare_tx_burst(struct rte_mbuf *pkts[], uint16_t nb_pkts, uint8_t port);

/* Enqueue a single packet, and send burst if queue is filled */
int32_t
send_single_packet(struct rte_mbuf *m, uint8_t port);

void inbound_sp_sa(struct sp_ctx *sp, struct sa_ctx *sa, struct traffic_type *ip,
                   uint16_t lim);

void outbound_sp(struct sp_ctx *sp, struct traffic_type *ip,
                 struct traffic_type *ipsec);

void route4_pkts(struct rt_ctx *rt_ctx, struct rte_mbuf *pkts[], uint8_t nb_pkts);

void route6_pkts(struct rt_ctx *rt_ctx, struct rte_mbuf *pkts[], uint8_t nb_pkts);

uint8_t
get_port_nb_rx_queues(const uint8_t port);

int32_t
init_lcore_rx_queues(void);

/* display usage */
void print_usage(const char *prgname);

int32_t
parse_portmask(const char *portmask);

int32_t
parse_decimal(const char *str);

void print_ethaddr(const char *name, const struct ether_addr *eth_addr);
