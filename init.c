/*
* sun
 */

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
#include <rte_string_fns.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_lpm.h>
#include <rte_acl.h>
#include <rte_lpm6.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_jhash.h>
#include <rte_cryptodev.h>
#include <rte_spinlock.h>

#include <rte_jobstats.h>
#include <rte_timer.h>
#include <rte_alarm.h>

#include "main.h"
#include "secgw.h"
#include "ipsec.h"

static uint8_t rss_intel_key[40] = {0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A};

struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = ETH_MQ_RX_RSS,
        .max_rx_pkt_len = ETHER_MAX_LEN,
        .split_hdr_size = 0,
        .header_split = 0,   /**< Header Split disabled */
        .hw_ip_checksum = 1, /**< IP checksum offload enabled */
        .hw_vlan_filter = 0, /**< VLAN filtering disabled */
        .jumbo_frame = 0,    /**< Jumbo Frame Support disabled */
        .hw_strip_crc = 0,   /**< CRC stripped by hardware */
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = rss_intel_key,
            .rss_hf = ETH_RSS_IPV4,
        },
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};

static void
app_assign_worker_ids(void)
{
    uint32_t lcore, worker_id;

    /* Assign ID for each worker */
    worker_id = 0;
    for (lcore = 0; lcore < APP_MAX_LCORES; lcore++)
    {
        struct app_lcore_params_worker *lp_worker = &app.lcore_params[lcore].worker;

        if (app.lcore_params[lcore].type != e_APP_LCORE_WORKER)
        {
            continue;
        }

        lp_worker->worker_id = worker_id;
        app.worker_id_to_lcore_id[worker_id] = lcore;

        worker_id++;
    }
    app.n_workers = worker_id;
}

static void
app_init_mbuf_pools(void)
{
    unsigned socket, lcore;

    /* Init the buffer pools */
    for (socket = 0; socket < APP_MAX_SOCKETS; socket++)
    {
        char name[32];
        if (app_is_socket_used(socket) == 0)
        {
            continue;
        }

        snprintf(name, sizeof(name), "mbuf_pool_%u", socket);
        printf("Creating the mbuf pool for socket %u ...\n", socket);
        app.pools[socket] = rte_pktmbuf_pool_create(
            name, APP_DEFAULT_MEMPOOL_BUFFERS,
            APP_DEFAULT_MEMPOOL_CACHE_SIZE,
            ipsec_metadata_size(), APP_DEFAULT_MBUF_DATA_SIZE, socket);
        if (app.pools[socket] == NULL)
        {
            rte_panic("Cannot create mbuf pool on socket %u\n", socket);
        }
    }

    for (lcore = 0; lcore < APP_MAX_LCORES; lcore++)
    {
        if (app.lcore_params[lcore].type == e_APP_LCORE_DISABLED)
        {
            continue;
        }

        socket = rte_lcore_to_socket_id(lcore);
        app.lcore_params[lcore].pool = app.pools[socket];
    }
}

static void
app_init_rings_rx(void)
{
    unsigned lcore;

    /* Initialize the rings for the RX side */
    for (lcore = 0; lcore < APP_MAX_LCORES; lcore++)
    {
        struct app_lcore_params_io *lp_io = &app.lcore_params[lcore].io;
        unsigned socket_io, lcore_worker;

        if ((app.lcore_params[lcore].type != e_APP_LCORE_IO) ||
            (lp_io->rx.n_nic_queues == 0))
        {
            continue;
        }

        socket_io = rte_lcore_to_socket_id(lcore);

        for (lcore_worker = 0; lcore_worker < APP_MAX_LCORES; lcore_worker++)
        {
            char name[32];
            struct app_lcore_params_worker *lp_worker = &app.lcore_params[lcore_worker].worker;
            struct rte_ring *ring = NULL;

            if (app.lcore_params[lcore_worker].type != e_APP_LCORE_WORKER)
            {
                continue;
            }

            printf("Creating ring to connect I/O lcore %u (socket %u) with worker lcore %u ...\n",
                   lcore,
                   socket_io,
                   lcore_worker);
            snprintf(name, sizeof(name), "app_ring_rx_s%u_io%u_w%u",
                     socket_io,
                     lcore,
                     lcore_worker);
            ring = rte_ring_create(
                name,
                app.ring_rx_size,
                socket_io,
                RING_F_SP_ENQ | RING_F_SC_DEQ);
            if (ring == NULL)
            {
                rte_panic("Cannot create ring to connect I/O core %u with worker core %u\n",
                          lcore,
                          lcore_worker);
            }

            lp_io->rx.rings[lp_io->rx.n_rings] = ring;
            lp_io->rx.n_rings++;

            lp_worker->rings_in[lp_worker->n_rings_in] = ring;
            lp_worker->n_rings_in++;
        }
    }

    for (lcore = 0; lcore < APP_MAX_LCORES; lcore++)
    {
        struct app_lcore_params_io *lp_io = &app.lcore_params[lcore].io;

        if ((app.lcore_params[lcore].type != e_APP_LCORE_IO) ||
            (lp_io->rx.n_nic_queues == 0))
        {
            continue;
        }

        if (lp_io->rx.n_rings != app_get_lcores_worker())
        {
            rte_panic("Algorithmic error (I/O RX rings)\n");
        }
    }

    for (lcore = 0; lcore < APP_MAX_LCORES; lcore++)
    {
        struct app_lcore_params_worker *lp_worker = &app.lcore_params[lcore].worker;

        if (app.lcore_params[lcore].type != e_APP_LCORE_WORKER)
        {
            continue;
        }

        if (lp_worker->n_rings_in != app_get_lcores_io_rx())
        {
            rte_panic("Algorithmic error (worker input rings)\n");
        }
    }
}

static void
app_init_rings_tx(void)
{
    unsigned lcore;

    /* Initialize the rings for the TX side */
    for (lcore = 0; lcore < APP_MAX_LCORES; lcore++)
    {
        struct app_lcore_params_worker *lp_worker = &app.lcore_params[lcore].worker;
        unsigned port;

        if (app.lcore_params[lcore].type != e_APP_LCORE_WORKER)
        {
            continue;
        }

        for (port = 0; port < APP_MAX_NIC_PORTS; port++)
        {
            char name[32];
            struct app_lcore_params_io *lp_io = NULL;
            struct rte_ring *ring;
            uint32_t socket_io, lcore_io;

            if (app.nic_tx_port_mask[port] == 0)
            {
                continue;
            }

            if (app_get_lcore_for_nic_tx((uint8_t)port, &lcore_io) < 0)
            {
                rte_panic("Algorithmic error (no I/O core to handle TX of port %u)\n",
                          port);
            }

            lp_io = &app.lcore_params[lcore_io].io;
            socket_io = rte_lcore_to_socket_id(lcore_io);

            printf("Creating ring to connect worker lcore %u with TX port %u (through I/O lcore %u) (socket %u) ...\n",
                   lcore, port, (unsigned)lcore_io, (unsigned)socket_io);
            snprintf(name, sizeof(name), "app_ring_tx_s%u_w%u_p%u", socket_io, lcore, port);
            ring = rte_ring_create(
                name,
                app.ring_tx_size,
                socket_io,
                RING_F_SP_ENQ | RING_F_SC_DEQ);
            if (ring == NULL)
            {
                rte_panic("Cannot create ring to connect worker core %u with TX port %u\n",
                          lcore,
                          port);
            }

            lp_worker->rings_out[port] = ring;
            lp_io->tx.rings[port][lp_worker->worker_id] = ring;
        }
    }

    for (lcore = 0; lcore < APP_MAX_LCORES; lcore++)
    {
        struct app_lcore_params_io *lp_io = &app.lcore_params[lcore].io;
        unsigned i;

        if ((app.lcore_params[lcore].type != e_APP_LCORE_IO) ||
            (lp_io->tx.n_nic_ports == 0))
        {
            continue;
        }

        for (i = 0; i < lp_io->tx.n_nic_ports; i++)
        {
            unsigned port, j;

            port = lp_io->tx.nic_ports[i];
            for (j = 0; j < app_get_lcores_worker(); j++)
            {
                if (lp_io->tx.rings[port][j] == NULL)
                {
                    rte_panic("Algorithmic error (I/O TX rings)\n");
                }
            }
        }
    }
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */
    uint8_t portid, count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;
    uint32_t n_rx_queues, n_tx_queues;

    printf("\nChecking link status");
    fflush(stdout);
    for (count = 0; count <= MAX_CHECK_TIME; count++)
    {
        all_ports_up = 1;
        for (portid = 0; portid < port_num; portid++)
        {
            if ((port_mask & (1 << portid)) == 0)
                continue;
            n_rx_queues = app_get_nic_rx_queues_per_port(portid);
            n_tx_queues = app.nic_tx_port_mask[portid];
            if ((n_rx_queues == 0) && (n_tx_queues == 0))
                continue;
            memset(&link, 0, sizeof(link));
            rte_eth_link_get_nowait(portid, &link);
            /* print link status if flag set */
            if (print_flag == 1)
            {
                if (link.link_status)
                    printf("Port %d Link Up - speed %u "
                           "Mbps - %s\n",
                           (uint8_t)portid,
                           (unsigned)link.link_speed,
                           (link.link_duplex == ETH_LINK_FULL_DUPLEX) ? ("full-duplex") : ("half-duplex\n"));
                else
                    printf("Port %d Link Down\n",
                           (uint8_t)portid);
                continue;
            }
            /* clear all_ports_up flag if any link down */
            if (link.link_status == ETH_LINK_DOWN)
            {
                all_ports_up = 0;
                break;
            }
        }
        /* after finally printing all link status, get out */
        if (print_flag == 1)
            break;

        if (all_ports_up == 0)
        {
            printf(".");
            fflush(stdout);
            rte_delay_ms(CHECK_INTERVAL);
        }

        /* set the print_flag if all ports up or timeout */
        if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1))
        {
            print_flag = 1;
            printf("done\n");
        }
    }
}

static void
app_init_nics(void)
{
    unsigned socket;
    uint32_t lcore;
    uint8_t port, queue;
    int ret;
    uint32_t n_rx_queues, n_tx_queues;

    /* Init NIC ports and queues, then start the ports */
    for (port = 0; port < APP_MAX_NIC_PORTS; port++)
    {
        struct rte_mempool *pool;

        n_rx_queues = app_get_nic_rx_queues_per_port(port);
        n_tx_queues = app.nic_tx_port_mask[port];

        if ((n_rx_queues == 0) && (n_tx_queues == 0))
        {
            continue;
        }

        /* Init port */
        printf("Initializing NIC port %u ...\n", (unsigned)port);
        ret = rte_eth_dev_configure(
            port,
            (uint8_t)n_rx_queues,
            (uint8_t)n_tx_queues,
            &port_conf);
        if (ret < 0)
        {
            rte_panic("Cannot init NIC port %u (%d)\n", (unsigned)port, ret);
        }
        rte_eth_promiscuous_enable(port);

        /* Init RX queues */
        for (queue = 0; queue < APP_MAX_RX_QUEUES_PER_NIC_PORT; queue++)
        {
            if (app.nic_rx_queue_mask[port][queue] == 0)
            {
                continue;
            }

            app_get_lcore_for_nic_rx(port, queue, &lcore);
            socket = rte_lcore_to_socket_id(lcore);
            pool = app.lcore_params[lcore].pool;

            printf("Initializing NIC port %u RX queue %u ...\n",
                   (unsigned)port,
                   (unsigned)queue);
            ret = rte_eth_rx_queue_setup(
                port,
                queue,
                (uint16_t)app.nic_rx_ring_size,
                socket,
                NULL,
                pool);
            if (ret < 0)
            {
                rte_panic("Cannot init RX queue %u for port %u (%d)\n",
                          (unsigned)queue,
                          (unsigned)port,
                          ret);
            }
        }

        /* Init TX queues */
        if (app.nic_tx_port_mask[port] == 1)
        {
            app_get_lcore_for_nic_tx(port, &lcore);
            socket = rte_lcore_to_socket_id(lcore);
            printf("Initializing NIC port %u TX queue 0 ...\n",
                   (unsigned)port);
            ret = rte_eth_tx_queue_setup(
                port,
                0,
                (uint16_t)app.nic_tx_ring_size,
                socket,
                NULL);
            if (ret < 0)
            {
                rte_panic("Cannot init TX queue 0 for port %d (%d)\n",
                          port,
                          ret);
            }
        }

        /* Start port */
        ret = rte_eth_dev_start(port);
        if (ret < 0)
        {
            rte_panic("Cannot start port %d (%d)\n", port, ret);
        }
    }

    check_all_ports_link_status(APP_MAX_NIC_PORTS, enabled_port_mask);
}

static void app_cryptodevs_init(void)
{
    struct rte_cryptodev_config dev_conf;
    struct rte_cryptodev_qp_conf qp_conf;
    uint32_t lcore, qp_id, max_nb_qps, n_workers;
    int cdev_id, n_cryptodevs, ret;
    char crypto_name[20];

    //create crypto_aesni_mb
    n_workers = app.n_workers;
    if (n_workers <= 0)
    {
        rte_exit(1, "Failed to init cryptodevs, because app.n_workers == %d", n_workers);
    }
    n_cryptodevs = n_workers % 8 ? n_workers / 8 + 1 : n_workers / 8;
    //debug
    printf("\n n_cryptodevs = %d\n", n_cryptodevs);

    for (cdev_id = 0; cdev_id < n_cryptodevs; cdev_id++)
    {
        snprintf(crypto_name, sizeof(crypto_name), "crypto_aesni_mb%d", cdev_id);
        ret = rte_eal_vdev_init(crypto_name, NULL);
        if (ret != 0)
            rte_exit(EXIT_FAILURE, "Cannot create virtual crypto device");
    }

    /* Assign crypto_dev_id and queue_paire_id for each worker */
    lcore = 0;
    for (cdev_id = rte_cryptodev_count() - 1; cdev_id >= 0; cdev_id--)
    {
        //debug
        printf("cryptodev count:%d \n", rte_cryptodev_count());
        printf("cdev_id : %d \n", cdev_id);
        //debug
        struct rte_cryptodev_info cdev_info;

        rte_cryptodev_info_get(cdev_id, &cdev_info);

        max_nb_qps = cdev_info.max_nb_queue_pairs;

        qp_id = 0;

        for (; lcore < APP_MAX_LCORES; lcore++)
        {
            struct app_lcore_params_worker *lp_worker = &app.lcore_params[lcore].worker;

            if (app.lcore_params[lcore].type != e_APP_LCORE_WORKER)
            {
                continue;
            }

            if (qp_id >= max_nb_qps)
            {
                break;
            }

            lp_worker->cdev_id_qp.id = cdev_id;
            lp_worker->cdev_id_qp.qp = qp_id;
            lp_worker->ipsec_conf.inbound.cdev_id_qp = &lp_worker->cdev_id_qp;
            lp_worker->ipsec_conf.outbound.cdev_id_qp = &lp_worker->cdev_id_qp;

            qp_id++;
        }

        //all workers have qp
        if (qp_id == 0)
        {
            break;
        }

        dev_conf.socket_id = rte_cryptodev_socket_id(cdev_id);
        dev_conf.nb_queue_pairs = qp_id;
        dev_conf.session_mp.nb_objs = CDEV_MP_NB_OBJS;
        dev_conf.session_mp.cache_size = CDEV_MP_CACHE_SZ;

        if (rte_cryptodev_configure(cdev_id, &dev_conf))
            rte_panic("Failed to initialize crypodev %u\n",
                      cdev_id);

        qp_conf.nb_descriptors = CDEV_QUEUE_DESC;
        for (qp_id = 0; qp_id < dev_conf.nb_queue_pairs; qp_id++)
            if (rte_cryptodev_queue_pair_setup(cdev_id, qp_id,
                                               &qp_conf, dev_conf.socket_id))
                rte_panic("Failed to setup queue %u for "
                          "cdev_id %u\n",
                          0, cdev_id);

        if (rte_cryptodev_start(cdev_id))
            rte_panic("Failed to start cryptodev %u\n",
                      cdev_id);
    }

    printf("\n");
}

static void pool_init(struct socket_ctx *ctx, int32_t socket_id)
{
    ctx->mbuf_pool = app.pools[socket_id];
    if (ctx->mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot init mbuf pool on socket %d\n",
                 socket_id);
    else
        printf("Allocated mbuf pool on socket %d\n", socket_id);
}

//初始化流重定向信息表hash表,以及节点负载信息表
static void
app_init_hash_table(void)
{
    struct rte_hash_parameters hash_parms = {
        .name = "flow_redirect_info_table", //暂时没有
        .entries = DEFAULT_HASH_ENTRIES,
        .key_len = sizeof(struct app_touple),
        .hash_func = DEFAULT_HASH_FUNC,
        .hash_func_init_val = 0,
    };

    //初始化重定向信息表
    app.flow_redirect_info_table = rte_hash_create(&hash_parms);
    app.n_flows = 0;
    if (app.flow_redirect_info_table == NULL)
    {
        rte_exit(EXIT_FAILURE, "app_init_hash_table -> Unable to create the flow_redirect_info_table hash\n");
    }
    printf("flow_redirect_info_table create successfully! \n");

    //初始化节点负载信息表
    uint32_t i;
    char name[64];

    for (i = 0; i < app.n_workers; i++)
    {
        snprintf(name, sizeof(name), "worker_%u_flow_ld_info_hash", i);
        struct rte_hash_parameters worker_hash_parms = {
            .name = name,
            .entries = DEFAULT_WORKER_HASH_ENTRIES,
            .key_len = sizeof(struct app_touple),
            .hash_func = DEFAULT_WORKER_HASH_FUNC,
            .hash_func_init_val = 0,
        };
        app.workers_ld_info[i].worker_flow_ld_info_hash = rte_hash_create(&worker_hash_parms);
        app.workers_ld_info[i].n_flows = 0;
        app.workers_ld_info[i].worker_id = i;
        app.workers_ld_info[i].worker_load_value = 0;

        if (app.workers_ld_info[i].worker_flow_ld_info_hash == NULL)
        {
            rte_exit(EXIT_FAILURE, "app.workers_ld_info[%d].worker_flow_ld_info_hash create failed!\n", i);
        }
    }
}

void app_init(void)
{
    uint32_t lcore_id, socket_id;

    app_assign_worker_ids();
    app_init_mbuf_pools();
    app_init_rings_rx();
    app_init_rings_tx();
    app_init_nics();
    app_init_hash_table();

    //------------ipsec----------------

    /* Replicate each contex per socket */
    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++)
    {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;

        socket_id = (uint8_t)rte_lcore_to_socket_id(lcore_id);

        if (socket_ctx[socket_id].mbuf_pool)
            continue;

        sa_init(&socket_ctx[socket_id], socket_id);

        sp4_init(&socket_ctx[socket_id], socket_id);

        sp6_init(&socket_ctx[socket_id], socket_id);

        rt_init(&socket_ctx[socket_id], socket_id);

        pool_init(&socket_ctx[socket_id], socket_id);
    }

    app_cryptodevs_init();

    printf("Initialization completed.\n");
}
