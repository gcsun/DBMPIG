/*
* sun
 */
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <rte_branch_prediction.h>
#include <rte_log.h>
#include <rte_crypto.h>
#include <rte_cryptodev.h>
#include <rte_mbuf.h>
#include <rte_hash.h>

#include "ipsec.h"
#include "esp.h"

static inline int
create_session(struct ipsec_ctx *ipsec_ctx __rte_unused, struct ipsec_sa *sa)
{

    RTE_LOG(DEBUG, IPSEC, "Create session for SA spi %u on cryptodev "
                          "%u qp %u\n",
            sa->spi,
            ipsec_ctx->cdev_id_qp->id,
            ipsec_ctx->cdev_id_qp->qp);

    sa->crypto_session = rte_cryptodev_sym_session_create(
        ipsec_ctx->cdev_id_qp->id, sa->xforms);

    return 0;
}

static inline void
enqueue_cop(struct cdev_qp *cqp, struct rte_crypto_op *cop)
{
    int32_t ret, i;

    cqp->buf[cqp->len++] = cop;

    if (cqp->len == MAX_PKT_BURST)
    {
        ret = rte_cryptodev_enqueue_burst(cqp->id, cqp->qp,
                                          cqp->buf, cqp->len);
        if (ret < cqp->len)
        {
            RTE_LOG(DEBUG, IPSEC, "Cryptodev %u queue %u:"
                                  " enqueued %u crypto ops out of %u\n",
                    cqp->id, cqp->qp,
                    ret, cqp->len);
            for (i = ret; i < cqp->len; i++)
                rte_pktmbuf_free(cqp->buf[i]->sym->m_src);
        }
        cqp->in_flight += ret;
        cqp->len = 0;
    }
}

static inline void
ipsec_enqueue(ipsec_xform_fn xform_func, struct ipsec_ctx *ipsec_ctx,
              struct rte_mbuf *pkts[], struct ipsec_sa *sas[],
              uint16_t nb_pkts)
{
    int32_t ret = 0, i;
    struct ipsec_mbuf_metadata *priv;
    struct ipsec_sa *sa;

    for (i = 0; i < nb_pkts; i++)
    {
        if (unlikely(sas[i] == NULL))
        {
            rte_pktmbuf_free(pkts[i]);
            continue;
        }

        rte_prefetch0(sas[i]);
        rte_prefetch0(pkts[i]);

        priv = get_priv(pkts[i]);
        sa = sas[i];
        priv->sa = sa;

        priv->cop.type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
        priv->cop.status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;

        rte_prefetch0(&priv->sym_cop);
        priv->cop.sym = &priv->sym_cop;

        if ((unlikely(sa->crypto_session == NULL)) &&
            create_session(ipsec_ctx, sa))
        {
            rte_pktmbuf_free(pkts[i]);
            continue;
        }

        rte_crypto_op_attach_sym_session(&priv->cop,
                                         sa->crypto_session);

        ret = xform_func(pkts[i], sa, &priv->cop);
        if (unlikely(ret))
        {
            rte_pktmbuf_free(pkts[i]);
            continue;
        }

        // RTE_ASSERT(sa->cdev_id_qp < ipsec_ctx->nb_qps);
        enqueue_cop(ipsec_ctx->cdev_id_qp, &priv->cop);
    }
}

static inline int
ipsec_dequeue(ipsec_xform_fn xform_func, struct ipsec_ctx *ipsec_ctx,
              struct rte_mbuf *pkts[], uint16_t max_pkts)
{
    int32_t nb_pkts = 0, ret = 0, j, nb_cops;
    struct ipsec_mbuf_metadata *priv;
    struct rte_crypto_op *cops[max_pkts];
    struct ipsec_sa *sa;
    struct rte_mbuf *pkt;
    struct cdev_qp *cqp;

    cqp = ipsec_ctx->cdev_id_qp;

    if (cqp->in_flight == 0)
        return 0;

    nb_cops = rte_cryptodev_dequeue_burst(cqp->id, cqp->qp,
                                          cops, max_pkts - nb_pkts);

    cqp->in_flight -= nb_cops;

    for (j = 0; j < nb_cops; j++)
    {
        pkt = cops[j]->sym->m_src;
        rte_prefetch0(pkt);

        priv = get_priv(pkt);
        sa = priv->sa;

        RTE_ASSERT(sa != NULL);

        ret = xform_func(pkt, sa, cops[j]);
        if (unlikely(ret))
            rte_pktmbuf_free(pkt);
        else
            pkts[nb_pkts++] = pkt;
    }

    /* return packets */
    return nb_pkts;
}

uint16_t
ipsec_inbound(struct ipsec_ctx *ctx, struct rte_mbuf *pkts[],
              uint16_t nb_pkts, uint16_t len)
{
    struct ipsec_sa *sas[nb_pkts];

    inbound_sa_lookup(ctx->sa_ctx, pkts, sas, nb_pkts);

    ipsec_enqueue(esp_inbound, ctx, pkts, sas, nb_pkts);

    return ipsec_dequeue(esp_inbound_post, ctx, pkts, len);
}

uint16_t
ipsec_outbound(struct ipsec_ctx *ctx, struct rte_mbuf *pkts[],
               uint32_t sa_idx[], uint16_t nb_pkts, uint16_t len)
{
    struct ipsec_sa *sas[nb_pkts];

    outbound_sa_lookup(ctx->sa_ctx, sa_idx, sas, nb_pkts);

    ipsec_enqueue(esp_outbound, ctx, pkts, sas, nb_pkts);

    return ipsec_dequeue(esp_outbound_post, ctx, pkts, len);
}
