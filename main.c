/*
* sun
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>

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
#include <rte_errno.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_lpm.h>
#include <rte_cryptodev.h>
#include <rte_spinlock.h>

#include <rte_jobstats.h>
#include <rte_timer.h>
#include <rte_alarm.h>

#include "main.h"
#include "secgw.h"

int main(int argc, char **argv)
{
    uint32_t lcore;
    uint32_t socket_id;
    struct app_worker_ipsec_conf *sconf;
    int ret;
    struct app_lcore_params *lp;
    struct app_lcore_params_worker *lp_worker;
    char name[RTE_JOBSTATS_NAMESIZE];

    /* Init EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        return -1;
    argc -= ret;
    argv += ret;

    /* Parse application arguments (after the EAL ones) */
    ret = app_parse_args(argc, argv);
    if (ret < 0)
    {
        app_print_usage();
        return -1;
    }

    /* Init */
    app_init();
    app_print_params();

    //初始化计时器相关库
    rte_timer_subsystem_init();

    /* fetch default timer frequency. */
    hz = rte_get_timer_hz();
    drain_tsc = (hz + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

    RTE_LCORE_FOREACH(lcore)
    {
        lp = &app.lcore_params[lcore];
        if (lp->type != e_APP_LCORE_WORKER)
        {
            continue;
        }
        lp_worker = &lp->worker;

        //初始化sp,sa,rt
        socket_id = rte_lcore_to_socket_id(lcore);
        sconf = &lp_worker->ipsec_conf;
        sconf->rt4_ctx = socket_ctx[socket_id].rt_ip4;
        sconf->rt6_ctx = socket_ctx[socket_id].rt_ip6;
        sconf->inbound.sp4_ctx = socket_ctx[socket_id].sp_ip4_in;
        sconf->inbound.sp6_ctx = socket_ctx[socket_id].sp_ip6_in;
        sconf->inbound.sa_ctx = socket_ctx[socket_id].sa_in;
        sconf->outbound.sp4_ctx = socket_ctx[socket_id].sp_ip4_out;
        sconf->outbound.sp6_ctx = socket_ctx[socket_id].sp_ip6_out;
        sconf->outbound.sa_ctx = socket_ctx[socket_id].sa_out;
        //初始化统计相关变量
        rte_spinlock_init(&lp_worker->lock);
        if (rte_jobstats_context_init(&lp_worker->jobs_context) != 0)
        {
            rte_panic("Jobs stats context for core %u init failed\n", lcore);
        }

        struct rte_jobstats *job = &lp_worker->process_job;
        snprintf(name, RTE_DIM(name), "worker %d job", lp_worker->worker_id);

        rte_jobstats_init(job, name, 0, drain_tsc, 0, MAX_PKT_BURST);
        rte_jobstats_set_update_period_function(job, worker_job_update_cb);

        rte_timer_init(&lp_worker->worker_timer);
        ret = rte_timer_reset(&lp_worker->worker_timer, 0, PERIODICAL, lcore,
                              &app_lcore_worker_job, (void *)lp_worker);

        if (ret < 0)
        {
            rte_exit(1, "Failed to reset lcore %u worker %u job timer: %s",
                     lcore, lp_worker->worker_id, rte_strerror(-ret));
        }
    }

    //定时输出端口统计信息
    rte_eal_alarm_set(timer_period * MS_PER_S, show_port_stats, NULL);

    if (app.dynamic)
    {
        printf("\ndynamic load balance up!\n");
        //定时进行负载均衡
        rte_eal_alarm_set(load_balance_timer_period * MS_PER_S, load_balance, NULL);
    }
    else
    {
        printf("\ndynamic load balance down!\n");
    }

    /* Launch per-lcore init on every lcore */
    //debug
    printf("\n master core id is :  %d \n", rte_lcore_id());

    rte_eal_mp_remote_launch(app_lcore_main_loop, NULL, SKIP_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore)
    {
        if (rte_eal_wait_lcore(lcore) < 0)
        {
            return -1;
        }
    }

    return 0;
}
