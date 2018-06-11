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
#include <rte_acl.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_lpm.h>
#include <rte_hash.h>

#include <rte_cryptodev.h>
#include <rte_spinlock.h>

#include <rte_jobstats.h>
#include <rte_timer.h>
#include <rte_alarm.h>

#include "ipsec.h"
#include "secgw.h"
#include "main.h"

/* default load balance period is 10 seconds */
int64_t load_balance_timer_period = APP_LOAD_BALANCE_PERIOD;

//获取数据包的ip元组信息
static void get_pkt_touple(struct rte_mbuf *pkt, struct app_touple *tpl)
{
    struct ipv4_hdr *ipv4_hdr = NULL;
    ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr *, sizeof(struct ether_hdr));

    tpl->src_ip = ipv4_hdr->src_addr;
    tpl->dst_ip = ipv4_hdr->dst_addr;
}

//根据worker_id 和 rte_mbuf pkt获取该流配置的加密算法
static enum app_crypto_algo get_pkt_crypto_algo(uint32_t worker_id, struct rte_mbuf *pkt)
{
    uint32_t lcore_id = app.worker_id_to_lcore_id[worker_id];
    struct app_lcore_params_worker *lp_worker = &app.lcore_params[lcore_id].worker;
    struct ipsec_ctx *ipsec_ctx = &lp_worker->ipsec_conf.outbound;
    uint8_t *nlp;
    struct ipsec_sa *sa;
    uint32_t res, sa_idx;
    enum app_crypto_algo flow_crypto;

    nlp = (uint8_t *)rte_pktmbuf_adj(pkt, ETHER_HDR_LEN);
    nlp = RTE_PTR_ADD(nlp, offsetof(struct ip, ip_p));

    rte_acl_classify((struct rte_acl_ctx *)ipsec_ctx->sp4_ctx, &nlp, &res,
                     1, DEFAULT_MAX_CATEGORIES);

    sa_idx = res & PROTECT_MASK;
    if ((res == 0) || (res & DISCARD))
        return NULL_CRYPTO;
    else if (sa_idx != 0)
    {
        //找到sa
        // sa = &sa_ctx->sa[sa_idx];
        outbound_sa_lookup(ipsec_ctx->sa_ctx, &sa_idx, &sa, 1);

        if (sa == NULL)
        {
            rte_exit(EXIT_FAILURE, "sa lookup failed in get_pkt_crypto_algo() \n");
        }
        else if (sa->cipher_algo == RTE_CRYPTO_CIPHER_AES_CBC)
        {

            switch (sa->cipher_key_len)
            {
            case 16:
                flow_crypto = AES_CBC_128;
                break;
            case 24:
                flow_crypto = AES_CBC_192;
                break;
            case 32:
                flow_crypto = AES_CBC_256;
                break;
            default:
                rte_exit(EXIT_FAILURE, "sa->cipher_key_len = %u cbc flow_crypto doesn't support in get_pkt_crypto_algo()\n", sa->cipher_key_len);
                break;
            }
        }
        else if (sa->cipher_algo == RTE_CRYPTO_CIPHER_AES_CTR)
        {
            switch (sa->cipher_key_len)
            {
            case 128:
                flow_crypto = AES_CTR_128;
                break;
            case 192:
                flow_crypto = AES_CTR_192;
                break;
            case 256:
                flow_crypto = AES_CTR_256;
                break;
            default:
                rte_exit(EXIT_FAILURE, "sa->cipher_key_len = %u ctr flow_crypto doesn't support in get_pkt_crypto_algo()\n", sa->cipher_key_len);
                break;
            }
        }
        else
        {
            rte_exit(EXIT_FAILURE, "sa lookup result abnormal in get_pkt_crypto_algo() \n");
        }
        return flow_crypto;
    }
    else /* BYPASS */
        return NULL_CRYPTO;
}

//接收数据包后，更新统计信息，以及最后得到转发到的worker_id
uint32_t get_forward_worker_id(struct rte_mbuf *pkt, uint32_t n_workers)
{
    struct app_touple tpl;
    struct hash_value *p_h_val = NULL;
    struct app_flow_load_info *p_flow_ld_info = NULL;
    struct app_worker_load_info *p_worker_info;
    struct rte_hash *p_flow_info_hash;
    uint32_t worker_id, rss_hash_ret;
    int ret;
    //获取数据包元组信息
    get_pkt_touple(pkt, &tpl);
    //查找转发表
    ret = rte_hash_lookup_data((const struct rte_hash *)app.flow_redirect_info_table, (const void *)&tpl, (void **)&p_h_val);
    //如果转发表找到相应记录
    if (ret >= 0)
    {
        worker_id = p_h_val->worker_id;
        //修改对应的流负载信息
        p_worker_info = &app.workers_ld_info[worker_id];
        p_flow_info_hash = p_worker_info->worker_flow_ld_info_hash;

        ret = rte_hash_lookup_data((const struct rte_hash *)p_flow_info_hash, (const void *)&tpl, (void **)&p_flow_ld_info);

        if (ret >= 0)
        {
            p_flow_ld_info->rx_pkts_num++;
        }
        else
        {
            rte_exit(EXIT_FAILURE, "flow hash lookup failed in worker %d \n", worker_id);
        }
    }
    else if (ret == -ENOENT)
    {
        //如果转发表没有找到相应记录,则按照静态负载均衡计算
        //计算worker_id
        rss_hash_ret = pkt->hash.rss;
        worker_id = rss_hash_ret & (n_workers - 1);
        //向hash表添加条目并更新统计信息，向WNFIT添加条目
        if (app.n_flows >= DEFAULT_HASH_ENTRIES)
        {
            rte_exit(EXIT_FAILURE, "flow num is too big to store in FRIT hash table \n");
        }
        app.flow_hash_values[app.n_flows].tpl.src_ip = tpl.src_ip;
        app.flow_hash_values[app.n_flows].tpl.dst_ip = tpl.dst_ip;
        app.flow_hash_values[app.n_flows].worker_id = worker_id;
        rte_hash_add_key_data(app.flow_redirect_info_table, (const void *)&tpl, (void *)&app.flow_hash_values[app.n_flows]);
        app.n_flows++;

        //添加到对应worker的负载信息结构中,这是第一次添加，所以进行一些变量的初始化
        p_worker_info = &app.workers_ld_info[worker_id];
        p_flow_info_hash = p_worker_info->worker_flow_ld_info_hash;

        if (p_worker_info->n_flows >= APP_WORKER_MAX_FLOW)
        {
            rte_exit(EXIT_FAILURE, "flow num is too big to store in worker %d flow hash table \n", worker_id);
        }
        p_flow_ld_info = &p_worker_info->worker_flow_ld_info[p_worker_info->n_flows];
        p_flow_ld_info->rx_pkts_num = 1;
        p_flow_ld_info->pkts_len = pkt->pkt_len;
        p_flow_ld_info->flow_crypto = get_pkt_crypto_algo(worker_id, pkt);
        p_flow_ld_info->tpl.src_ip = tpl.src_ip;
        p_flow_ld_info->tpl.dst_ip = tpl.dst_ip;
        p_flow_ld_info->flow_load_value = 0;

        rte_hash_add_key_data(p_flow_info_hash, (const void *)&tpl, (void *)p_flow_ld_info);

        p_worker_info->n_flows++;
    }
    else if (ret == -EINVAL)
    {
        printf("ret == %d\n", ret);
        rte_exit(EXIT_FAILURE, "get_forward_worker_id -> hash table lookup failed\n");
    }
    else
    {
        printf("ret == %d\n", ret);
        rte_exit(EXIT_FAILURE, "get_forward_worker_id -> hash table lookup failed---ret yichang\n");
    }

    return worker_id;
}

//计算单条流的负载值
static void calculate_flow_load_value(struct app_flow_load_info *flow_ld_info)
{
    //首先常数D为0.32mpps,约为320kpps,也就是3200kp/(10s)
    uint64_t D_cst = 3200;
    //数据包长 pkts_len
    uint64_t pkts_len = flow_ld_info->pkts_len;
    //加密算法影响因数,单位是kp/(10s)
    uint64_t p_crpt;

    if (pkts_len <= 128)
    {
        p_crpt = 0;
    }
    else
    {
        p_crpt = flow_ld_info->flow_crypto;
    }

    //10s内接受的数据包总数，注意单位是个，使其换算为kp/(10s)
    uint64_t rx_pkts = flow_ld_info->rx_pkts_num / 1024;

    //求T_max极限转发速率
    uint64_t T_max;

    if (pkts_len <= 500)
    {
        T_max = D_cst - p_crpt;
    }
    else if (pkts_len <= 900)
    {
        T_max = 4300 - 2 * pkts - p_crpt;
    }
    else
    {
        T_max = 3400 - pkts_len;
    }

    //计算接收的数据包占极限转发速率的百分比
    uint64_t fl_ld_val = rx_pkts * 100 / T_max;

    if (fl_ld_val > 100)
    {
        fl_ld_val = 100;
    }

    flow_ld_info->flow_load_value = fl_ld_val;

    //初始化接受包数，其他的不用在这里复位
    flow_ld_info->rx_pkts_num = 0;
}

//计算单节点worker的负载值
static void calculate_worker_load_value(uint32_t worker_id)
{
    struct app_worker_load_info *worker_ld_info = &app.workers_ld_info[worker_id];
    struct app_flow_load_info *flow_ld_info;
    uint32_t flow_id;

    worker_ld_info->worker_load_value = 0;

    for (flow_id = 0; flow_id < worker_ld_info->n_flows; flow_id++)
    {
        flow_ld_info = &worker_ld_info->worker_flow_ld_info[flow_id];
        calculate_flow_load_value(flow_ld_info);
        worker_ld_info->worker_load_value += flow_ld_info->flow_load_value;
    }
}
//begin end均为可达位置，不是边界位置
void quick_sort(struct app_worker_load_info *workers_sorted[], uint32_t begin, uint32_t end)
{
    uint32_t i, j;
    struct app_worker_load_info *temp;

    if (begin < end)
    {
        i = begin;
        j = end;
        temp = workers_sorted[i];

        while (i < j)
        {
            while (i < j && workers_sorted[j]->worker_load_value < temp->worker_load_value)
            {
                j--;
            }
            if (i < j)
            {
                workers_sorted[i++] = workers_sorted[j];
            }

            while (i < j && workers_sorted[i]->worker_load_value > temp->worker_load_value)
            {
                i++;
            }
            if (i < j)
            {
                workers_sorted[j--] = workers_sorted[i];
            }
        }

        workers_sorted[i] = temp;
        if (likely(i != 0))
        {
            quick_sort(workers_sorted, begin, i - 1);
        }
        quick_sort(workers_sorted, i + 1, end);
    }
}
//按照节点负载值降序排序节点指针数组
//workers_sorted[]必须由外部传进来，否则就是个局部变量，无法再外部使用的
static void decrease_sort_worker(struct app_worker_load_info *workers_sorted[])
{
    uint32_t worker_num = app.n_workers;
    uint32_t worker_id;
    //初始化workers_sorted[]
    for (worker_id = 0; worker_id < worker_num; worker_id++)
    {
        workers_sorted[worker_id] = &app.workers_ld_info[worker_id];
    }

    //排序
    quick_sort(workers_sorted, 0, worker_num - 1);

    //debug
    //输出排序结果
    uint32_t i;
    for (i = 0; i < worker_num; i++)
    {
        printf("\nworker_id = %u , worker_load_value = %" PRIu64 "\n",
               workers_sorted[i]->worker_id, workers_sorted[i]->worker_load_value);
    }
}

/*分类节点
*load_heavy_index  重负载节点的边界,所指位置为重负载节点的最后一个
*load_heavy_incr  重负载节点的分类标准，超过或者等于该值认为是重负载节点
*workers_sorted   按照负载值排好序的工作节点结构体指针
*ret  0:存在重负载节点 -1：不存在重负载节点 -2：不存在非重负载节点
*/
static int classify_worker(uint32_t *load_heavy_index, double load_heavy_incr,
                           struct app_worker_load_info *workers_sorted[], uint32_t worker_num)
{
    struct app_worker_load_info *worker;
    uint32_t worker_id;
    int ret = 0;

    //降序排序worker
    decrease_sort_worker(workers_sorted);

    for (worker_id = 0; worker_id < worker_num; worker_id++)
    {
        worker = workers_sorted[worker_id];
        if (worker->worker_load_value < load_heavy_incr)
        {
            *load_heavy_index = worker_id - 1;
            break;
        }
    }

    //如果不存在重负载节点,不再继续分类
    if (worker_id == 0)
    {
        ret = -1;
        printf("%s", "No heavy load nodes were found!\n");
        return ret;
    }
    //如果找不到非重负载节点，都是重负载节点
    if (worker_id == worker_num)
    {
        ret = -2;
        return ret;
    }
    return ret;
}

//按照平均负载值，将重负载节点上的流迁移到轻负载节点上，采取从n_flows处倒序迁移的顺序
static int transfer_flows(uint32_t load_heavy_index, double load_heavy_incr,
                          struct app_worker_load_info *workers_sorted[], uint32_t worker_num)
{
    uint32_t hvy_worker_id = 0;
    uint32_t lit_worker_id = worker_num - 1;
    struct app_touple *trans_flow_touple;

    struct app_worker_load_info *heavy_worker = workers_sorted[hvy_worker_id];
    struct app_worker_load_info *light_worker = workers_sorted[lit_worker_id];
    struct app_flow_load_info *heavy_flow;
    struct app_flow_load_info *light_flow;

    struct hash_value *p_h_val;
    int ret, load_balance_res;

    for (;;)
    {
        if (heavy_worker->worker_load_value < load_heavy_incr)
        {
            hvy_worker_id++;
            if (hvy_worker_id > load_heavy_index)
            {
                //所有重负载节点都迁移完毕
                load_balance_res = 0;
                break;
            }
            heavy_worker = workers_sorted[hvy_worker_id];
        }
        //选取待迁移的流
        heavy_flow = &heavy_worker->worker_flow_ld_info[heavy_worker->n_flows - 1];

        for (lit_worker_id = worker_num - 1; lit_worker_id > load_heavy_index; lit_worker_id--)
        {
            light_worker = workers_sorted[lit_worker_id];
            if (light_worker->worker_load_value < load_heavy_incr)
            {
                break;
            }
        }
        if (lit_worker_id == load_heavy_index)
        {
            //所有轻负载节点都无法接收当前待迁移流
            load_balance_res = -1;
            break;
        }

        //找到第一个符合要求的轻负载节点，获得待迁移流要迁移到的位置
        light_flow = &light_worker->worker_flow_ld_info[light_worker->n_flows];

        light_flow->rx_pkts_num = 0;
        light_flow->flow_crypto = heavy_flow->flow_crypto;
        light_flow->pkts_len = heavy_flow->pkts_len;
        light_flow->tpl.src_ip = heavy_flow->tpl.src_ip;
        light_flow->tpl.dst_ip = heavy_flow->tpl.dst_ip;
        light_flow->flow_load_value = 0;

        //待迁移流的元组信息
        trans_flow_touple = &light_flow->tpl;

        //重负载节点删除hash项，轻负载节点添加hash项
        rte_hash_add_key_data(light_worker->worker_flow_ld_info_hash, (const void *)trans_flow_touple, (void *)light_flow);
        rte_hash_del_key(heavy_worker->worker_flow_ld_info_hash, (const void *)trans_flow_touple);

        //根据trans_flow_touple将该流在重定向表里的worker_id指向现在的轻负载节点
        ret = rte_hash_lookup_data((const struct rte_hash *)app.flow_redirect_info_table, (const void *)trans_flow_touple, (void **)&p_h_val);
        if (ret >= 0)
        {
            p_h_val->worker_id = light_worker->worker_id;
        }
        else
        {
            rte_exit(EXIT_FAILURE, "transfer_flows() -> redirect hash table lookup failed \n");
        }
        //更新两个节点的节点负载值
        heavy_worker->worker_load_value -= heavy_flow->flow_load_value;
        light_worker->worker_load_value += heavy_flow->flow_load_value;
        //更新两个节点的n_flows
        heavy_worker->n_flows--;
        light_worker->n_flows++;
    }

    return load_balance_res;
}

//整个负载均衡的过程
void load_balance(__rte_unused void *param)
{
    //计算所有节点的节点负载值
    uint32_t i, load_heavy_index;
    double load_heavy_incr = 0.8;
    struct app_worker_load_info *workers_sorted[app.n_workers];
    int ret, ld_ret;

    for (i = 0; i < app.n_workers; i++)
    {
        calculate_worker_load_value(i);
    }

    //分类节点
    ret = classify_worker(&load_heavy_index, load_heavy_incr,
                          workers_sorted, app.n_workers);

    if (ret == 0)
    {
        ld_ret = transfer_flows(load_heavy_index, load_heavy_incr,
                                workers_sorted, app.n_workers);

        if (ld_ret == 0)
        {
            //负载均衡成功，所有重负载节点都进行了流迁移
            printf("\n load balance successful! \n");
        }
        else if (ld_ret == -1)
        {
            /* 重负载节点没有都平衡完 */
            printf("\n load balance failed! There is still heavy load nodes!\n");
        }
    }
    else if (ret == -1)
    {
        printf("\n No heavy load nodes were found! No load balancing is required. \n");
    }
    else if (ret == -2)
    {
        printf("\n No light load nodes were found! Unable to load balancing. \n");
    }

    rte_eal_alarm_set(load_balance_timer_period * US_PER_S, load_balance, NULL);
}
