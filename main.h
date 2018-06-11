/*
 sun
*/

#ifndef _MAIN_H_
#define _MAIN_H_

#include "ipsec.h"

/* Logical cores */
#ifndef APP_MAX_SOCKETS
#define APP_MAX_SOCKETS 2
#endif

#ifndef APP_MAX_LCORES
#define APP_MAX_LCORES RTE_MAX_LCORE
#endif

#ifndef APP_MAX_NIC_PORTS
#define APP_MAX_NIC_PORTS RTE_MAX_ETHPORTS
#endif

#ifndef APP_MAX_RX_QUEUES_PER_NIC_PORT
#define APP_MAX_RX_QUEUES_PER_NIC_PORT 128
#endif

#ifndef APP_MAX_TX_QUEUES_PER_NIC_PORT
#define APP_MAX_TX_QUEUES_PER_NIC_PORT 128
#endif

#ifndef APP_MAX_IO_LCORES
#define APP_MAX_IO_LCORES 16
#endif
#if (APP_MAX_IO_LCORES > APP_MAX_LCORES)
#error "APP_MAX_IO_LCORES is too big"
#endif

#ifndef APP_MAX_NIC_RX_QUEUES_PER_IO_LCORE
#define APP_MAX_NIC_RX_QUEUES_PER_IO_LCORE 16
#endif

#ifndef APP_MAX_NIC_TX_PORTS_PER_IO_LCORE
#define APP_MAX_NIC_TX_PORTS_PER_IO_LCORE 16
#endif
#if (APP_MAX_NIC_TX_PORTS_PER_IO_LCORE > APP_MAX_NIC_PORTS)
#error "APP_MAX_NIC_TX_PORTS_PER_IO_LCORE too big"
#endif

#ifndef APP_MAX_WORKER_LCORES
#define APP_MAX_WORKER_LCORES 120
#endif
#if (APP_MAX_WORKER_LCORES > APP_MAX_LCORES)
#error "APP_MAX_WORKER_LCORES is too big"
#endif

/* Mempools */
#ifndef APP_DEFAULT_MBUF_DATA_SIZE
#define APP_DEFAULT_MBUF_DATA_SIZE RTE_MBUF_DEFAULT_BUF_SIZE
#endif

#ifndef APP_DEFAULT_MEMPOOL_BUFFERS
#define APP_DEFAULT_MEMPOOL_BUFFERS 8192 * 8
#endif

#ifndef APP_DEFAULT_MEMPOOL_CACHE_SIZE
#define APP_DEFAULT_MEMPOOL_CACHE_SIZE 512
#endif

/* LPM Tables */
#ifndef APP_MAX_LPM_RULES
#define APP_MAX_LPM_RULES 1024
#endif

/* NIC RX */
#ifndef APP_DEFAULT_NIC_RX_RING_SIZE
#define APP_DEFAULT_NIC_RX_RING_SIZE 1024
#endif

/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
#ifndef APP_DEFAULT_NIC_RX_PTHRESH
#define APP_DEFAULT_NIC_RX_PTHRESH 8
#endif

#ifndef APP_DEFAULT_NIC_RX_HTHRESH
#define APP_DEFAULT_NIC_RX_HTHRESH 8
#endif

#ifndef APP_DEFAULT_NIC_RX_WTHRESH
#define APP_DEFAULT_NIC_RX_WTHRESH 4
#endif

#ifndef APP_DEFAULT_NIC_RX_FREE_THRESH
#define APP_DEFAULT_NIC_RX_FREE_THRESH 64
#endif

#ifndef APP_DEFAULT_NIC_RX_DROP_EN
#define APP_DEFAULT_NIC_RX_DROP_EN 0
#endif

/* NIC TX */
#ifndef APP_DEFAULT_NIC_TX_RING_SIZE
#define APP_DEFAULT_NIC_TX_RING_SIZE 1024
#endif

/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
#ifndef APP_DEFAULT_NIC_TX_PTHRESH
#define APP_DEFAULT_NIC_TX_PTHRESH 36
#endif

#ifndef APP_DEFAULT_NIC_TX_HTHRESH
#define APP_DEFAULT_NIC_TX_HTHRESH 0
#endif

#ifndef APP_DEFAULT_NIC_TX_WTHRESH
#define APP_DEFAULT_NIC_TX_WTHRESH 0
#endif

#ifndef APP_DEFAULT_NIC_TX_FREE_THRESH
#define APP_DEFAULT_NIC_TX_FREE_THRESH 0
#endif

#ifndef APP_DEFAULT_NIC_TX_RS_THRESH
#define APP_DEFAULT_NIC_TX_RS_THRESH 0
#endif

/* Software Rings */
#ifndef APP_DEFAULT_RING_RX_SIZE
#define APP_DEFAULT_RING_RX_SIZE 1024
#endif

#ifndef APP_DEFAULT_RING_TX_SIZE
#define APP_DEFAULT_RING_TX_SIZE 1024
#endif

/* Bursts */
#ifndef APP_MBUF_ARRAY_SIZE
#define APP_MBUF_ARRAY_SIZE 512
#endif

#ifndef APP_DEFAULT_BURST_SIZE_IO_RX_READ
#define APP_DEFAULT_BURST_SIZE_IO_RX_READ 32
#endif
#if (APP_DEFAULT_BURST_SIZE_IO_RX_READ > APP_MBUF_ARRAY_SIZE)
#error "APP_DEFAULT_BURST_SIZE_IO_RX_READ is too big"
#endif

#ifndef APP_DEFAULT_BURST_SIZE_IO_RX_WRITE
#define APP_DEFAULT_BURST_SIZE_IO_RX_WRITE 32
#endif
#if (APP_DEFAULT_BURST_SIZE_IO_RX_WRITE > APP_MBUF_ARRAY_SIZE)
#error "APP_DEFAULT_BURST_SIZE_IO_RX_WRITE is too big"
#endif

#ifndef APP_DEFAULT_BURST_SIZE_IO_TX_READ
#define APP_DEFAULT_BURST_SIZE_IO_TX_READ 32
#endif
#if (APP_DEFAULT_BURST_SIZE_IO_TX_READ > APP_MBUF_ARRAY_SIZE)
#error "APP_DEFAULT_BURST_SIZE_IO_TX_READ is too big"
#endif

#ifndef APP_DEFAULT_BURST_SIZE_IO_TX_WRITE
#define APP_DEFAULT_BURST_SIZE_IO_TX_WRITE 32
#endif
#if (APP_DEFAULT_BURST_SIZE_IO_TX_WRITE > APP_MBUF_ARRAY_SIZE)
#error "APP_DEFAULT_BURST_SIZE_IO_TX_WRITE is too big"
#endif

#ifndef APP_DEFAULT_BURST_SIZE_WORKER_READ
#define APP_DEFAULT_BURST_SIZE_WORKER_READ 32
#endif
#if ((2 * APP_DEFAULT_BURST_SIZE_WORKER_READ) > APP_MBUF_ARRAY_SIZE)
#error "APP_DEFAULT_BURST_SIZE_WORKER_READ is too big"
#endif

#ifndef APP_DEFAULT_BURST_SIZE_WORKER_WRITE
#define APP_DEFAULT_BURST_SIZE_WORKER_WRITE 32
#endif
#if (APP_DEFAULT_BURST_SIZE_WORKER_WRITE > APP_MBUF_ARRAY_SIZE)
#error "APP_DEFAULT_BURST_SIZE_WORKER_WRITE is too big"
#endif

/* 1 day max */
#define MAX_TIMER_PERIOD 86400
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define UPDATE_STEP_UP 1
#define UPDATE_STEP_DOWN 32
#define APP_SHOW_STATS_PERIOD 5 /* 统计数据输出的周期 */

//流重定向hash表用到的默认信息
#ifndef DEFAULT_HASH_ENTRIES
#define DEFAULT_HASH_ENTRIES 10240
#endif
#ifndef DEFAULT_HASH_FUNC
#define DEFAULT_HASH_FUNC rte_hash_crc
#endif
//worker节点中流表信息hash表默认配置
#ifndef DEFAULT_WORKER_HASH_ENTRIES
#define DEFAULT_WORKER_HASH_ENTRIES 10240
#endif
#ifndef DEFAULT_WORKER_HASH_FUNC
#define DEFAULT_WORKER_HASH_FUNC rte_hash_crc
#endif

//工作节点做多负载的流的数目
#ifndef APP_WORKER_MAX_FLOW
#define APP_WORKER_MAX_FLOW 1024
#endif

//负载均衡周期
#define APP_LOAD_BALANCE_PERIOD 30

//本体统支持的加密算法，用来对应流负载信息中的加密算法附加值，单位是kp/(10s)
enum app_crypto_algo
{
    NULL_CRYPTO = -300,
    AES_CBC_128 = 0,
    AES_CBC_192 = 0,
    AES_CBC_256 = 205,
    AES_CTR_128 = 0,
    AES_CTR_192 = 0,
    AES_CTR_256 = 205
};

//元组信息
struct app_touple
{
    uint32_t src_ip;
    uint32_t dst_ip;
};

//重定向hash表中，存储信息的结构体
struct hash_value
{
    struct app_touple tpl;
    uint8_t worker_id;
};

//流负载信息结构体
struct app_flow_load_info
{
    uint64_t rx_pkts_num;             //周期内收到的包数，作为收包频率
    enum app_crypto_algo flow_crypto; //流所配置的加密算法对应的负载加成值
    uint32_t pkts_len;
    struct app_touple tpl;
    uint64_t flow_load_value;
};

//节点负载信息结构体
struct app_worker_load_info
{
    struct app_flow_load_info worker_flow_ld_info[APP_WORKER_MAX_FLOW];
    struct rte_hash *worker_flow_ld_info_hash;
    uint32_t n_flows;
    uint32_t worker_id;
    uint64_t worker_load_value;
};

struct app_mbuf_array
{
    struct rte_mbuf *array[APP_MBUF_ARRAY_SIZE];
    uint32_t n_mbufs;
};

enum app_lcore_type
{
    e_APP_LCORE_DISABLED = 0,
    e_APP_LCORE_IO,
    e_APP_LCORE_WORKER
};

struct app_lcore_params_io
{
    /* I/O RX */
    struct
    {
        /* NIC */
        struct
        {
            uint8_t port;
            uint8_t queue;
        } nic_queues[APP_MAX_NIC_RX_QUEUES_PER_IO_LCORE];
        uint32_t n_nic_queues;

        /* Rings */
        struct rte_ring *rings[APP_MAX_WORKER_LCORES];
        uint32_t n_rings;

        /* Internal buffers */
        struct app_mbuf_array mbuf_in;
        struct app_mbuf_array mbuf_out[APP_MAX_WORKER_LCORES];
        uint8_t mbuf_out_flush[APP_MAX_WORKER_LCORES];

    } rx;

    /* I/O TX */
    struct
    {
        /* Rings */
        struct rte_ring *rings[APP_MAX_NIC_PORTS][APP_MAX_WORKER_LCORES];

        /* NIC */
        uint8_t nic_ports[APP_MAX_NIC_TX_PORTS_PER_IO_LCORE];
        uint32_t n_nic_ports;

        /* Internal buffers */
        struct app_mbuf_array mbuf_out[APP_MAX_NIC_TX_PORTS_PER_IO_LCORE];
        uint8_t mbuf_out_flush[APP_MAX_NIC_TX_PORTS_PER_IO_LCORE];

    } tx;
};

struct app_worker_ipsec_conf
{
    struct ipsec_ctx inbound;
    struct ipsec_ctx outbound;
    struct rt_ctx *rt4_ctx;
    struct rt_ctx *rt6_ctx;
} __rte_cache_aligned;

struct app_lcore_params_worker
{
    /* Rings */
    struct rte_ring *rings_in[APP_MAX_IO_LCORES];
    uint32_t n_rings_in;
    struct rte_ring *rings_out[APP_MAX_NIC_PORTS];

    /* LPM table */
    struct rte_lpm *lpm_table;
    uint32_t worker_id;

    /* ipsec */
    struct cdev_qp cdev_id_qp;
    struct app_worker_ipsec_conf ipsec_conf;

    /* Internal buffers */
    struct app_mbuf_array mbuf_in;
    struct app_mbuf_array mbuf_out[APP_MAX_NIC_PORTS];
    uint8_t mbuf_out_flush[APP_MAX_NIC_PORTS];

    /* Stats */
    struct rte_timer worker_timer;
    struct rte_jobstats process_job;
    struct rte_jobstats idle_job;
    struct rte_jobstats_context jobs_context;

    rte_atomic16_t stats_read_pending;
    rte_spinlock_t lock;
};

struct app_lcore_params
{
    union {
        struct app_lcore_params_io io;
        struct app_lcore_params_worker worker;
    };
    enum app_lcore_type type;
    struct rte_mempool *pool;
} __rte_cache_aligned;

struct app_lpm_rule
{
    uint32_t ip;
    uint8_t depth;
    uint8_t if_out;
};

struct app_params
{
    /* lcore */
    struct app_lcore_params lcore_params[APP_MAX_LCORES];
    uint32_t n_workers;
    //建立通过worker_id获得lcore_id的数组
    uint32_t worker_id_to_lcore_id[APP_MAX_WORKER_LCORES];

    /* NIC */
    uint8_t nic_rx_queue_mask[APP_MAX_NIC_PORTS][APP_MAX_RX_QUEUES_PER_NIC_PORT];
    uint8_t nic_tx_port_mask[APP_MAX_NIC_PORTS];

    /* mbuf pools */
    struct rte_mempool *pools[APP_MAX_SOCKETS];

    /* LPM tables */
    struct rte_lpm *lpm_tables[APP_MAX_SOCKETS];
    struct app_lpm_rule lpm_rules[APP_MAX_LPM_RULES];
    uint32_t n_lpm_rules;

    /* rings */
    uint32_t nic_rx_ring_size;
    uint32_t nic_tx_ring_size;
    uint32_t ring_rx_size;
    uint32_t ring_tx_size;

    /* burst size */
    uint32_t burst_size_io_rx_read;
    uint32_t burst_size_io_rx_write;
    uint32_t burst_size_io_tx_read;
    uint32_t burst_size_io_tx_write;
    uint32_t burst_size_worker_read;
    uint32_t burst_size_worker_write;

    //动态负载均衡
    uint64_t heavy_load_threshold;
    struct rte_hash *flow_redirect_info_table;
    /* 存储重定向hash表指向的value值,流数目非常大时可能需要优化方法，超时无效的记录如何清除以及再利用*/
    struct hash_value flow_hash_values[DEFAULT_HASH_ENTRIES];
    uint64_t n_flows;
    //节点负载信息表,按照worker_id存取
    struct app_worker_load_info workers_ld_info[APP_MAX_WORKER_LCORES];

    //是否启动动态负载均衡  0  静态   1  静态+动态
    uint32_t dynamic;

} __rte_cache_aligned;

extern struct app_params app;

/* default period is 10 seconds */
extern int64_t timer_period;
/* default timer frequency */
extern double hz;
/* BURST_TX_DRAIN_US converted to cycles */
extern uint64_t drain_tsc;

/* default load balance period is 10 seconds */
int64_t load_balance_timer_period;

int app_parse_args(int argc, char **argv);
void app_print_usage(void);
void app_init(void);
int app_lcore_main_loop(void *arg);

int app_get_nic_rx_queues_per_port(uint8_t port);
int app_get_lcore_for_nic_rx(uint8_t port, uint8_t queue, uint32_t *lcore_out);
int app_get_lcore_for_nic_tx(uint8_t port, uint32_t *lcore_out);
int app_is_socket_used(uint32_t socket);
uint32_t app_get_lcores_io_rx(void);
uint32_t app_get_lcores_worker(void);
void app_print_params(void);

//负载统计
void show_port_stats(__rte_unused void *param);
void worker_job_update_cb(struct rte_jobstats *job, int64_t result);
void app_lcore_worker_job(__rte_unused struct rte_timer *timer, void *arg);

//关于负载均衡的相关操作api
void quick_sort(struct app_worker_load_info *workers_sorted[], uint32_t begin, uint32_t end);
uint32_t get_forward_worker_id(struct rte_mbuf *pkt, uint32_t n_workers);
void load_balance(__rte_unused void *param);

#endif /* _MAIN_H_ */
