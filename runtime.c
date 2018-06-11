/*
 sun
*/

#include <locale.h>
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
#include <ctype.h>
#include <errno.h>
#include <getopt.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
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
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
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

#include "main.h"
#include "secgw.h"

#ifndef APP_LCORE_IO_FLUSH
#define APP_LCORE_IO_FLUSH 1000000
#endif

#ifndef APP_LCORE_WORKER_FLUSH
#define APP_LCORE_WORKER_FLUSH 1000000
#endif

#define APP_IO_RX_DROP_ALL_PACKETS 0
#define APP_WORKER_DROP_ALL_PACKETS 0
#define APP_IO_TX_DROP_ALL_PACKETS 0

#ifndef APP_IO_RX_PREFETCH_ENABLE
#define APP_IO_RX_PREFETCH_ENABLE 1
#endif

#ifndef APP_WORKER_PREFETCH_ENABLE
#define APP_WORKER_PREFETCH_ENABLE 1
#endif

#ifndef APP_IO_TX_PREFETCH_ENABLE
#define APP_IO_TX_PREFETCH_ENABLE 1
#endif

#if APP_IO_RX_PREFETCH_ENABLE
#define APP_IO_RX_PREFETCH0(p) rte_prefetch0(p)
#define APP_IO_RX_PREFETCH1(p) rte_prefetch1(p)
#else
#define APP_IO_RX_PREFETCH0(p)
#define APP_IO_RX_PREFETCH1(p)
#endif

#if APP_WORKER_PREFETCH_ENABLE
#define APP_WORKER_PREFETCH0(p) rte_prefetch0(p)
#define APP_WORKER_PREFETCH1(p) rte_prefetch1(p)
#else
#define APP_WORKER_PREFETCH0(p)
#define APP_WORKER_PREFETCH1(p)
#endif

#if APP_IO_TX_PREFETCH_ENABLE
#define APP_IO_TX_PREFETCH0(p) rte_prefetch0(p)
#define APP_IO_TX_PREFETCH1(p) rte_prefetch1(p)
#else
#define APP_IO_TX_PREFETCH0(p)
#define APP_IO_TX_PREFETCH1(p)
#endif

/* default period is 10 seconds */
int64_t timer_period = APP_SHOW_STATS_PERIOD;
/* default timer frequency */
double hz;
/* BURST_TX_DRAIN_US converted to cycles */
uint64_t drain_tsc;

/* Convert cycles to ns */
static inline double
cycles_to_ns(uint64_t cycles)
{
    double t = cycles;

    t *= (double)NS_PER_S;
    t /= hz;
    return t;
}

static inline void
app_lcore_io_rx_buffer_to_send(
    struct app_lcore_params_io *lp,
    uint32_t worker,
    struct rte_mbuf *mbuf,
    uint32_t bsz)
{
    uint32_t pos;
    int ret;

    pos = lp->rx.mbuf_out[worker].n_mbufs;
    lp->rx.mbuf_out[worker].array[pos++] = mbuf;
    if (likely(pos < bsz))
    {
        lp->rx.mbuf_out[worker].n_mbufs = pos;
        return;
    }

    ret = rte_ring_sp_enqueue_bulk(
        lp->rx.rings[worker],
        (void **)lp->rx.mbuf_out[worker].array,
        bsz);

    if (unlikely(ret == -ENOBUFS))
    {
        uint32_t k;
        for (k = 0; k < bsz; k++)
        {
            struct rte_mbuf *m = lp->rx.mbuf_out[worker].array[k];
            rte_pktmbuf_free(m);
        }
    }

    lp->rx.mbuf_out[worker].n_mbufs = 0;
    lp->rx.mbuf_out_flush[worker] = 0;
}

static inline void
app_lcore_io_rx(
    struct app_lcore_params_io *lp,
    uint32_t n_workers,
    uint32_t bsz_rd,
    uint32_t bsz_wr)
{
    struct rte_mbuf *mbuf_1_0, *mbuf_1_1, *mbuf_2_0, *mbuf_2_1;
    uint32_t i;

    for (i = 0; i < lp->rx.n_nic_queues; i++)
    {
        uint8_t port = lp->rx.nic_queues[i].port;
        uint8_t queue = lp->rx.nic_queues[i].queue;
        uint32_t n_mbufs, j;

        n_mbufs = rte_eth_rx_burst(
            port,
            queue,
            lp->rx.mbuf_in.array,
            (uint16_t)bsz_rd);

        if (unlikely(n_mbufs <= 0))
        {
            continue;
        }

        mbuf_1_0 = lp->rx.mbuf_in.array[0];
        mbuf_1_1 = lp->rx.mbuf_in.array[1];
        mbuf_2_0 = lp->rx.mbuf_in.array[2];
        mbuf_2_1 = lp->rx.mbuf_in.array[3];
        APP_IO_RX_PREFETCH0(mbuf_2_0);
        APP_IO_RX_PREFETCH0(mbuf_2_1);

        for (j = 0; j + 3 < n_mbufs; j += 2)
        {
            struct rte_mbuf *mbuf_0_0, *mbuf_0_1;
            uint32_t worker_0, worker_1;

            mbuf_0_0 = mbuf_1_0;
            mbuf_0_1 = mbuf_1_1;

            mbuf_1_0 = mbuf_2_0;
            mbuf_1_1 = mbuf_2_1;
            APP_IO_RX_PREFETCH0(mbuf_1_0);
            APP_IO_RX_PREFETCH0(mbuf_1_1);

            mbuf_2_0 = lp->rx.mbuf_in.array[j + 4];
            mbuf_2_1 = lp->rx.mbuf_in.array[j + 5];
            APP_IO_RX_PREFETCH0(mbuf_2_0);
            APP_IO_RX_PREFETCH0(mbuf_2_1);

            //获取数据包需要转发到的worker_id
            worker_0 = get_forward_worker_id(mbuf_0_0, n_workers);
            worker_1 = get_forward_worker_id(mbuf_0_1, n_workers);
            //debug
            // worker_0 = 0;
            // worker_1 = 0;

            app_lcore_io_rx_buffer_to_send(lp, worker_0, mbuf_0_0, bsz_wr);
            app_lcore_io_rx_buffer_to_send(lp, worker_1, mbuf_0_1, bsz_wr);
        }

        /* Handle the last 1, 2 (when n_mbufs is even) or 3 (when n_mbufs is odd) packets  */
        for (; j < n_mbufs; j += 1)
        {
            struct rte_mbuf *mbuf;
            uint32_t worker;

            mbuf = mbuf_1_0;
            mbuf_1_0 = mbuf_1_1;
            mbuf_1_1 = mbuf_2_0;
            mbuf_2_0 = mbuf_2_1;

            APP_IO_RX_PREFETCH0(mbuf_1_0);
            worker = get_forward_worker_id(mbuf, n_workers);
            //debug
            // worker = 0;
            app_lcore_io_rx_buffer_to_send(lp, worker, mbuf, bsz_wr);
        }
    }
}

static inline void
app_lcore_io_rx_flush(struct app_lcore_params_io *lp, uint32_t n_workers)
{
    uint32_t worker;

    for (worker = 0; worker < n_workers; worker++)
    {
        int ret;

        if (likely((lp->rx.mbuf_out_flush[worker] == 0) ||
                   (lp->rx.mbuf_out[worker].n_mbufs == 0)))
        {
            lp->rx.mbuf_out_flush[worker] = 1;
            continue;
        }

        ret = rte_ring_sp_enqueue_bulk(
            lp->rx.rings[worker],
            (void **)lp->rx.mbuf_out[worker].array,
            lp->rx.mbuf_out[worker].n_mbufs);

        if (unlikely(ret < 0))
        {
            uint32_t k;
            for (k = 0; k < lp->rx.mbuf_out[worker].n_mbufs; k++)
            {
                struct rte_mbuf *pkt_to_free = lp->rx.mbuf_out[worker].array[k];
                rte_pktmbuf_free(pkt_to_free);
            }
        }

        lp->rx.mbuf_out[worker].n_mbufs = 0;
        lp->rx.mbuf_out_flush[worker] = 1;
    }
}

static float
show_lcore_stats(unsigned lcore_id)
{
    struct app_lcore_params_worker *lp_worker = &app.lcore_params[lcore_id].worker;
    struct rte_jobstats_context *ctx = &lp_worker->jobs_context;

    /* LCore statistics. */
    uint64_t stats_period, loop_count;
    uint64_t exec, exec_min, exec_max;
    uint64_t management, management_min, management_max;
    uint64_t busy, busy_min, busy_max;

    uint64_t idle_exec_cnt;
    uint64_t idle_exec, idle_exec_min, idle_exec_max;

    uint64_t collection_time = rte_get_timer_cycles();

    //向工作线程请求读取数据
    rte_atomic16_set(&lp_worker->stats_read_pending, 1);
    rte_spinlock_lock(&lp_worker->lock);
    rte_atomic16_set(&lp_worker->stats_read_pending, 0);

    /* Collect context statistics. */
    stats_period = ctx->state_time - ctx->start_time;
    loop_count = ctx->loop_cnt;

    exec = ctx->exec_time;
    exec_min = ctx->min_exec_time;
    exec_max = ctx->max_exec_time;

    management = ctx->management_time;
    management_min = ctx->min_management_time;
    management_max = ctx->max_management_time;

    rte_jobstats_context_reset(ctx);

    idle_exec_cnt = lp_worker->idle_job.exec_cnt;
    idle_exec = lp_worker->idle_job.exec_time;
    idle_exec_min = lp_worker->idle_job.min_exec_time;
    idle_exec_max = lp_worker->idle_job.max_exec_time;
    rte_jobstats_reset(&lp_worker->idle_job);

    rte_spinlock_unlock(&lp_worker->lock);

    exec -= idle_exec;
    busy = exec + management;
    busy_min = exec_min + management_min;
    busy_max = exec_max + management_max;

    collection_time = rte_get_timer_cycles() - collection_time;

#define STAT_FMT "\n%-18s %'14.0f %6.1f%% %'10.0f %'10.0f %'10.0f"

    printf("\n----------------"
           "\nLCore %3u: statistics (time in ns, collected in %'9.0f)"
           "\n%-18s %14s %7s %10s %10s %10s "
           "\n%-18s %'14.0f"
           "\n%-18s %'14" PRIu64
               STAT_FMT              /* Exec */
                   STAT_FMT          /* Management */
                       STAT_FMT      /* Busy */
                           STAT_FMT, /* Idle  */
           lcore_id, cycles_to_ns(collection_time),
           "Stat type", "total", "%total", "avg", "min", "max",
           "Stats duration:", cycles_to_ns(stats_period),
           "Loop count:", loop_count,
           "Exec time",
           cycles_to_ns(exec), exec * 100.0 / stats_period,
           cycles_to_ns(loop_count ? exec / loop_count : 0),
           cycles_to_ns(exec_min),
           cycles_to_ns(exec_max),
           "Management time",
           cycles_to_ns(management), management * 100.0 / stats_period,
           cycles_to_ns(loop_count ? management / loop_count : 0),
           cycles_to_ns(management_min),
           cycles_to_ns(management_max),
           "Exec + management",
           cycles_to_ns(busy), busy * 100.0 / stats_period,
           cycles_to_ns(loop_count ? busy / loop_count : 0),
           cycles_to_ns(busy_min),
           cycles_to_ns(busy_max),
           "Idle (job)",
           cycles_to_ns(idle_exec), idle_exec * 100.0 / stats_period,
           cycles_to_ns(idle_exec_cnt ? idle_exec / idle_exec_cnt : 0),
           cycles_to_ns(idle_exec_min),
           cycles_to_ns(idle_exec_max));

    return exec * 100.0 / stats_period;
}

void show_port_stats(__rte_unused void *param)
{
    unsigned port, lcore_id, n_rx_queues, n_tx_queues;
    struct app_lcore_params *lp;

    const char clr[] = {27, '[', '2', 'J', '\0'};
    const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};

    //debug
    // printf("\n show_port_stats is called by lcore :  %d \n", rte_lcore_id());

    /* Clear screen and move to top left */
    printf("%s%s"
           "\nPort statistics ===================================",
           clr, topLeft);

    for (port = 0; port < APP_MAX_NIC_PORTS; port++)
    {
        if ((enabled_port_mask & (1 << port)) == 0)
            continue;

        n_rx_queues = app_get_nic_rx_queues_per_port(port);
        n_tx_queues = app.nic_tx_port_mask[port];
        if ((n_rx_queues == 0) && (n_tx_queues == 0))
        {
            continue;
        }

        //获取端口统计信息
        struct rte_eth_stats stats;
        rte_eth_stats_get(port, &stats);

        printf("\nStatistics for port %u ------------------------------"
               "\nPackets received: %20" PRIu64
               "\nPackets sent: %24" PRIu64
               "\nPackets rx dropped: %18" PRIu64
               "\nPackets tx dropped: %18" PRIu64,
               port,
               stats.ipackets,
               stats.opackets,
               stats.imissed,
               stats.oerrors);
        rte_eth_stats_reset(port);
    }

    //输出worker lcore的统计信息
    const char stats_file[] = {"lcore_stats.sun"};
    FILE *f = fopen(stats_file, "ab+");
    fprintf(f, "%s\n", "==============");
    float lcore_ld_val;

    RTE_LCORE_FOREACH(lcore_id)
    {
        lp = &app.lcore_params[lcore_id];
        if (lp->type != e_APP_LCORE_WORKER)
        {
            continue;
        }
        // show_lcore_stats(lcore_id);

        lcore_ld_val = show_lcore_stats(lcore_id);
        fprintf(f, "%3.1f\n", lcore_ld_val);
    }
    fprintf(f, "%d\n", app.n_workers);
    fclose(f);

    printf("\n====================================================\n");
    rte_eal_alarm_set(timer_period * US_PER_S, show_port_stats, NULL);
}

void worker_job_update_cb(struct rte_jobstats *job, int64_t result)
{
    int64_t err = job->target - result;
    int64_t histeresis = job->target / 8;

    if (err < -histeresis)
    {
        if (job->min_period + UPDATE_STEP_DOWN < job->period)
            job->period -= UPDATE_STEP_DOWN;
    }
    else if (err > histeresis)
    {
        if (job->period + UPDATE_STEP_UP < job->max_period)
            job->period += UPDATE_STEP_UP;
    }
}

static inline void
app_lcore_io_tx(
    struct app_lcore_params_io *lp,
    uint32_t n_workers,
    uint32_t bsz_rd,
    uint32_t bsz_wr)
{
    uint32_t worker;

    for (worker = 0; worker < n_workers; worker++)
    {
        uint32_t i;

        for (i = 0; i < lp->tx.n_nic_ports; i++)
        {
            uint8_t port = lp->tx.nic_ports[i];
            struct rte_ring *ring = lp->tx.rings[port][worker];
            uint32_t n_mbufs, n_pkts;
            int ret;

            n_mbufs = lp->tx.mbuf_out[port].n_mbufs;
            ret = rte_ring_sc_dequeue_bulk(
                ring,
                (void **)&lp->tx.mbuf_out[port].array[n_mbufs],
                bsz_rd);

            if (unlikely(ret == -ENOENT))
            {
                continue;
            }

            n_mbufs += bsz_rd;

            if (unlikely(n_mbufs < bsz_wr))
            {
                lp->tx.mbuf_out[port].n_mbufs = n_mbufs;
                continue;
            }

            //发送前准备
            prepare_tx_burst((struct rte_mbuf **)lp->tx.mbuf_out[port].array, bsz_wr, port);

            n_pkts = rte_eth_tx_burst(
                port,
                0,
                lp->tx.mbuf_out[port].array,
                (uint16_t)n_mbufs);

            if (unlikely(n_pkts < n_mbufs))
            {
                uint32_t k;
                for (k = n_pkts; k < n_mbufs; k++)
                {
                    struct rte_mbuf *pkt_to_free = lp->tx.mbuf_out[port].array[k];
                    rte_pktmbuf_free(pkt_to_free);
                }
            }
            lp->tx.mbuf_out[port].n_mbufs = 0;
            lp->tx.mbuf_out_flush[port] = 0;
        }
    }
}

static inline void
app_lcore_io_tx_flush(struct app_lcore_params_io *lp)
{
    uint8_t port;
    uint32_t i;

    for (i = 0; i < lp->tx.n_nic_ports; i++)
    {
        uint32_t n_pkts;

        port = lp->tx.nic_ports[i];
        if (likely((lp->tx.mbuf_out_flush[port] == 0) ||
                   (lp->tx.mbuf_out[port].n_mbufs == 0)))
        {
            lp->tx.mbuf_out_flush[port] = 1;
            continue;
        }

        n_pkts = rte_eth_tx_burst(
            port,
            0,
            lp->tx.mbuf_out[port].array,
            (uint16_t)lp->tx.mbuf_out[port].n_mbufs);

        if (unlikely(n_pkts < lp->tx.mbuf_out[port].n_mbufs))
        {
            uint32_t k;
            for (k = n_pkts; k < lp->tx.mbuf_out[port].n_mbufs; k++)
            {
                struct rte_mbuf *pkt_to_free = lp->tx.mbuf_out[port].array[k];
                rte_pktmbuf_free(pkt_to_free);
            }
        }

        lp->tx.mbuf_out[port].n_mbufs = 0;
        lp->tx.mbuf_out_flush[port] = 1;
    }
}

static void
app_lcore_main_loop_io(void)
{
    uint32_t lcore = rte_lcore_id();
    struct app_lcore_params_io *lp = &app.lcore_params[lcore].io;
    uint32_t n_workers = app_get_lcores_worker();
    uint64_t i = 0;

    uint32_t bsz_rx_rd = app.burst_size_io_rx_read;
    uint32_t bsz_rx_wr = app.burst_size_io_rx_write;
    uint32_t bsz_tx_rd = app.burst_size_io_tx_read;
    uint32_t bsz_tx_wr = app.burst_size_io_tx_write;

    for (;;)
    {
        if (likely(lp->rx.n_nic_queues > 0))
        {
            app_lcore_io_rx(lp, n_workers, bsz_rx_rd, bsz_rx_wr);
        }

        if (likely(lp->tx.n_nic_ports > 0))
        {
            app_lcore_io_tx(lp, n_workers, bsz_tx_rd, bsz_tx_wr);
        }

        i++;
    }
}

static inline void
prepare_one_ipsec_packet(struct rte_mbuf *pkt, struct ipsec_traffic *in_t, struct ipsec_traffic *out_t)
{
    uint8_t *nlp;
    struct ether_hdr *eth;
    struct ipsec_traffic *t;
    uint8_t portid;

    portid = pkt->port;
    if (UNPROTECTED_PORT(portid))
    {
        t = in_t;
    }
    else
    {
        t = out_t;
    }

    eth = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
    if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4))
    {
        nlp = (uint8_t *)rte_pktmbuf_adj(pkt, ETHER_HDR_LEN);
        nlp = RTE_PTR_ADD(nlp, offsetof(struct ip, ip_p));

        //debug
        // printf("\n nlp == %d\n", *nlp);

        if (*nlp == IPPROTO_ESP)
            t->ipsec.pkts[(t->ipsec.num)++] = pkt;
        else
        {
            t->ip4.data[t->ip4.num] = nlp;
            t->ip4.pkts[(t->ip4.num)++] = pkt;
        }
        t->pkts_num++;
    }
    else if (eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6))
    {
        nlp = (uint8_t *)rte_pktmbuf_adj(pkt, ETHER_HDR_LEN);
        nlp = RTE_PTR_ADD(nlp, offsetof(struct ip6_hdr, ip6_nxt));
        if (*nlp == IPPROTO_ESP)
            t->ipsec.pkts[(t->ipsec.num)++] = pkt;
        else
        {
            t->ip6.data[t->ip6.num] = nlp;
            t->ip6.pkts[(t->ip6.num)++] = pkt;
        }
        t->pkts_num++;
    }
    else
    {
        /* Unknown/Unsupported type, drop the packet */
        // RTE_LOG(ERR, IPSEC, "Unsupported packet type: %d \n", eth->ether_type);
        rte_pktmbuf_free(pkt);
    }
}

static inline void
prepare_ipsec_traffic(struct rte_mbuf **pkts, struct ipsec_traffic *in_t,
                      struct ipsec_traffic *out_t, uint16_t nb_pkts)
{
    int32_t i;

    in_t->ipsec.num = 0;
    in_t->ip4.num = 0;
    in_t->ip6.num = 0;
    in_t->pkts_num = 0;

    out_t->ipsec.num = 0;
    out_t->ip4.num = 0;
    out_t->ip6.num = 0;
    out_t->pkts_num = 0;

    for (i = 0; i < (nb_pkts - PREFETCH_OFFSET); i++)
    {
        rte_prefetch0(rte_pktmbuf_mtod(pkts[i + PREFETCH_OFFSET],
                                       void *));
        prepare_one_ipsec_packet(pkts[i], in_t, out_t);
    }
    /* Process left packets */
    for (; i < nb_pkts; i++)
        prepare_one_ipsec_packet(pkts[i], in_t, out_t);

    //debug
    // printf("\nin_t->ipsec.num = %d , in_t->ip4.num = %d \n", in_t->ipsec.num, in_t->ip4.num);
    // printf("\nout_t->ipsec.num = %d , out_t->ip4.num = %d \n", out_t->ipsec.num, out_t->ip4.num);
}

static inline void
ipsec_process_pkts_inbound(struct app_lcore_params_worker *lp,
                           struct ipsec_traffic *traffic)
{
    struct rte_mbuf *m;
    uint16_t idx, nb_pkts_in, i, n_ip4, n_ip6;
    struct ipsec_ctx *ipsec_ctx;

    ipsec_ctx = &lp->ipsec_conf.inbound;

    nb_pkts_in = ipsec_inbound(ipsec_ctx, traffic->ipsec.pkts,
                               traffic->ipsec.num, MAX_PKT_BURST);

    n_ip4 = traffic->ip4.num;
    n_ip6 = traffic->ip6.num;

    /* SP/ACL Inbound check ipsec and ip4 */
    for (i = 0; i < nb_pkts_in; i++)
    {
        m = traffic->ipsec.pkts[i];
        struct ip *ip = rte_pktmbuf_mtod(m, struct ip *);
        if (ip->ip_v == IPVERSION)
        {
            idx = traffic->ip4.num++;
            traffic->ip4.pkts[idx] = m;
            traffic->ip4.data[idx] = rte_pktmbuf_mtod_offset(m,
                                                             uint8_t *, offsetof(struct ip, ip_p));
        }
        else if (ip->ip_v == IP6_VERSION)
        {
            idx = traffic->ip6.num++;
            traffic->ip6.pkts[idx] = m;
            traffic->ip6.data[idx] = rte_pktmbuf_mtod_offset(m,
                                                             uint8_t *,
                                                             offsetof(struct ip6_hdr, ip6_nxt));
        }
        else
            rte_pktmbuf_free(m);
    }

    inbound_sp_sa(ipsec_ctx->sp4_ctx, ipsec_ctx->sa_ctx, &traffic->ip4,
                  n_ip4);

    inbound_sp_sa(ipsec_ctx->sp6_ctx, ipsec_ctx->sa_ctx, &traffic->ip6,
                  n_ip6);
}

static inline void
ipsec_process_pkts_outbound(struct app_lcore_params_worker *lp,
                            struct ipsec_traffic *traffic)
{
    struct rte_mbuf *m;
    uint16_t idx, nb_pkts_out, i;
    struct ipsec_ctx *ipsec_ctx;

    ipsec_ctx = &lp->ipsec_conf.outbound;

    /* Drop any IPsec traffic from protected ports */
    for (i = 0; i < traffic->ipsec.num; i++)
        rte_pktmbuf_free(traffic->ipsec.pkts[i]);

    traffic->ipsec.num = 0;

    outbound_sp(ipsec_ctx->sp4_ctx, &traffic->ip4, &traffic->ipsec);

    outbound_sp(ipsec_ctx->sp6_ctx, &traffic->ip6, &traffic->ipsec);

    nb_pkts_out = ipsec_outbound(ipsec_ctx, traffic->ipsec.pkts,
                                 traffic->ipsec.res, traffic->ipsec.num,
                                 MAX_PKT_BURST);

    for (i = 0; i < nb_pkts_out; i++)
    {
        m = traffic->ipsec.pkts[i];
        struct ip *ip = rte_pktmbuf_mtod(m, struct ip *);
        if (ip->ip_v == IPVERSION)
        {
            idx = traffic->ip4.num++;
            traffic->ip4.pkts[idx] = m;
        }
        else
        {
            idx = traffic->ip6.num++;
            traffic->ip6.pkts[idx] = m;
        }
    }
}

static inline void
ipsec_process_pkts(struct app_lcore_params_worker *lp, struct rte_mbuf **pkts,
                   uint8_t nb_pkts)
{
    struct ipsec_traffic inbound_traffic;
    struct ipsec_traffic outbound_traffic;

    prepare_ipsec_traffic(pkts, &inbound_traffic, &outbound_traffic, nb_pkts);

    if (inbound_traffic.pkts_num != 0)
    {
        //debug
        // printf("\ninbound traffic\n");

        ipsec_process_pkts_inbound(lp, &inbound_traffic);
        route4_pkts(lp->ipsec_conf.rt4_ctx, inbound_traffic.ip4.pkts, inbound_traffic.ip4.num);
        route6_pkts(lp->ipsec_conf.rt6_ctx, inbound_traffic.ip6.pkts, inbound_traffic.ip6.num);
    }

    if (outbound_traffic.pkts_num != 0)
    {
        //debug
        // printf("\noutbound traffic\n");

        ipsec_process_pkts_outbound(lp, &outbound_traffic);
        route4_pkts(lp->ipsec_conf.rt4_ctx, outbound_traffic.ip4.pkts, outbound_traffic.ip4.num);
        route6_pkts(lp->ipsec_conf.rt6_ctx, outbound_traffic.ip6.pkts, outbound_traffic.ip6.num);
    }
}

void app_lcore_worker_job(__rte_unused struct rte_timer *timer, void *arg)
{
    uint32_t bsz_rd;
    const unsigned lcore_id = rte_lcore_id();
    struct app_lcore_params_worker *lp;
    struct rte_jobstats *job;
    int ret;

    lp = (struct app_lcore_params_worker *)arg;

    job = &lp->process_job;

    //统计任务开始
    rte_jobstats_start(&lp->jobs_context, job);

    bsz_rd = app.burst_size_worker_read;

    struct rte_ring *ring_in = lp->rings_in[0];

    ret = rte_ring_sc_dequeue_bulk(ring_in, (void **)lp->mbuf_in.array, bsz_rd);

    if (unlikely(ret == -ENOENT))
    {
        //调整工作周期
        if (rte_jobstats_finish(job, 0) != 0)
        {
            rte_timer_reset(&lp->worker_timer, job->period, PERIODICAL,
                            lcore_id, app_lcore_worker_job, arg);
        }

        return;
    }

    ipsec_process_pkts(lp, lp->mbuf_in.array, bsz_rd);

    //调整工作周期
    if (rte_jobstats_finish(job, bsz_rd) != 0)
    {
        rte_timer_reset(&lp->worker_timer, job->period, PERIODICAL,
                        lcore_id, app_lcore_worker_job, arg);
    }
}

static inline void
app_lcore_worker_flush(struct app_lcore_params_worker *lp)
{
    uint32_t port;

    for (port = 0; port < APP_MAX_NIC_PORTS; port++)
    {
        int ret;

        if (unlikely(lp->rings_out[port] == NULL))
        {
            continue;
        }

        if (likely((lp->mbuf_out_flush[port] == 0) ||
                   (lp->mbuf_out[port].n_mbufs == 0)))
        {
            lp->mbuf_out_flush[port] = 1;
            continue;
        }

        ret = rte_ring_sp_enqueue_bulk(
            lp->rings_out[port],
            (void **)lp->mbuf_out[port].array,
            lp->mbuf_out[port].n_mbufs);

        if (unlikely(ret < 0))
        {
            uint32_t k;
            for (k = 0; k < lp->mbuf_out[port].n_mbufs; k++)
            {
                struct rte_mbuf *pkt_to_free = lp->mbuf_out[port].array[k];
                rte_pktmbuf_free(pkt_to_free);
            }
        }

        lp->mbuf_out[port].n_mbufs = 0;
        lp->mbuf_out_flush[port] = 1;
    }
}

static void
app_lcore_main_loop_worker(uint32_t lcore_id)
{

    uint8_t stats_read_pending;
    uint8_t need_manage;
    struct app_lcore_params_worker *lp_worker;

    lp_worker = &app.lcore_params[lcore_id].worker;
    stats_read_pending = 0;
    need_manage = 0;

    rte_jobstats_init(&lp_worker->idle_job, "idle", 0, 0, 0, 0);

    for (;;)
    {
        rte_spinlock_lock(&lp_worker->lock);

        do
        {
            rte_jobstats_context_start(&lp_worker->jobs_context);
            rte_jobstats_start(&lp_worker->jobs_context, &lp_worker->idle_job);

            uint64_t repeats = 0;

            need_manage = 0;
            do
            {
                uint64_t now = rte_get_timer_cycles();

                repeats++;

                stats_read_pending = rte_atomic16_read(&lp_worker->stats_read_pending);
                need_manage |= stats_read_pending;

                if (!need_manage)
                {
                    need_manage = lp_worker->worker_timer.expire < now;
                }
            } while (!need_manage);

            if (likely(repeats != 1))
            {
                rte_jobstats_finish(&lp_worker->idle_job, lp_worker->idle_job.target);
            }
            else
            {
                rte_jobstats_abort(&lp_worker->idle_job);
            }

            rte_timer_manage();

            rte_jobstats_context_finish(&lp_worker->jobs_context);

        } while (likely(stats_read_pending == 0));

        rte_spinlock_unlock(&lp_worker->lock);
        rte_pause();
    }
}

int app_lcore_main_loop(__attribute__((unused)) void *arg)
{
    struct app_lcore_params *lp;
    unsigned lcore;

    lcore = rte_lcore_id();

    lp = &app.lcore_params[lcore];

    if (lp->type == e_APP_LCORE_IO)
    {
        printf("Logical core %u (I/O) main loop.\n", lcore);
        app_lcore_main_loop_io();
    }

    if (lp->type == e_APP_LCORE_WORKER)
    {
        printf("Logical core %u (worker %u) main loop.\n",
               lcore,
               (unsigned)lp->worker.worker_id);

        app_lcore_main_loop_worker(lcore);
    }

    return 0;
}
