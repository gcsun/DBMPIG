/*
* sun
 */
#ifndef __RTE_IPSEC_XFORM_ESP_H__
#define __RTE_IPSEC_XFORM_ESP_H__

struct mbuf;

/* RFC4303 */
struct esp_hdr
{
    uint32_t spi;
    uint32_t seq;
    /* Payload */
    /* Padding */
    /* Pad Length */
    /* Next Header */
    /* Integrity Check Value - ICV */
};

int esp_inbound(struct rte_mbuf *m, struct ipsec_sa *sa,
                struct rte_crypto_op *cop);

int esp_inbound_post(struct rte_mbuf *m, struct ipsec_sa *sa,
                     struct rte_crypto_op *cop);

int esp_outbound(struct rte_mbuf *m, struct ipsec_sa *sa,
                 struct rte_crypto_op *cop);

int esp_outbound_post(struct rte_mbuf *m, struct ipsec_sa *sa,
                      struct rte_crypto_op *cop);

#endif /* __RTE_IPSEC_XFORM_ESP_H__ */
