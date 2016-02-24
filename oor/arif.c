
/*
 * 5 Tuple (muarif)
 * put this in lisp_message_fields.h
 */

/*
 *      0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           AFI = 16387         |     Rsvd1     |     Flags     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Type = 16    |     Rsvd2     |             4 + n            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         Lower Src-port        |         Upper Src-port        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         Lower Dst-port        |         Upper Dst-port        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    Reserved   |   Protocol    |   Source-ML   |    Dest-ML    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |              AFI = x          |         Source-Prefix ...     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |              AFI = x          |     Destination-Prefix ...    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

#include "lbuf.h"

typedef struct _lcaf_ftpl_hdr_t{
    uint16_t    afi;
    uint8_t     rsvd1;
    uint8_t     flags;
    uint8_t     type;
    uint8_t     rsvd2;
    uint16_t    len;
} __attribute__ ((__packed__)) lcaf_ftpl_hdr_t;

/*
 * lisp_lcaf.h
 */

typedef struct {
    lisp_addr_t                     src_addr;
    lisp_addr_t                     dst_addr;
    uint16_t                        src_port;
    uint16_t                        dst_port;
    uint8_t                         protocol;
} lisp_5tuple_t;

typedef struct {
	uint16_t	src_lp;
	uint16_t	src_up;
	uint16_t	dst_lp;
	uint16_t	dst_up;
	uint16_t	reserved;
	uint32_t	protocol;
    uint16_t	src_mlen;
    uint16_t	dst_mlen;
    lisp_addr_t	*src_pref;
    lisp_addr_t	*dst_pref;
} ftpl_t;



/*
 * LCAF Function
 * put in the lisp_lcaf.c
 */

lcaf_addr_t *
lcaf_addr_new_type(uint8_t type)
{
    lcaf_addr_t *lcaf;
    lcaf = xzalloc(sizeof(lcaf_addr_t));
    lcaf_addr_set_type(lcaf, type);

    switch(type) {
        case LCAF_IID:
            lcaf->addr = iid_type_new();
            break;
        case LCAF_MCAST_INFO:
            lcaf->addr = mc_type_new();
            break;
        case LCAF_GEO:
            break;
        case LCAF_FTPL:
        	lcaf->addr = ftpl_type_new();
        	break;
        default:
            break;
    }

    return(lcaf);
}

inline ftpl_t *
ftpl_type_new()
{
    ftpl_t *ftpl;
    ftpl = xzalloc(sizeof(ftpl_t));
    return(ftpl);
}

ftpl_t *
ftpl_type_new_init(lbuf_t *b,  lisp_5tuple_t *ltuple, lisp_addr_t *addr,)
{
    ftpl_t *ftplt = ftpl_type_new();
    struct iphdr *iph = NULL;
    struct ip6_hdr *ip6h = NULL;
    struct udphdr *udp = NULL;
    struct tcphdr *tcp = NULL;
    lbuf_t packet = *b;

    iph = lbuf_ip(&packet);

    lisp_addr_set_lafi(&tuple->src_addr, LM_AFI_IP);
    lisp_addr_set_lafi(&tuple->dst_addr, LM_AFI_IP);


    switch (iph->version) {
        case 4:
            lisp_addr_ip_init(&ltuple->src_addr, &iph->saddr, AF_INET);
            lisp_addr_ip_init(&ltuple->dst_addr, &iph->daddr, AF_INET);
            ltuple->protocol = iph->protocol;
            lbuf_pull(&packet, iph->ihl * 4);
            break;
        case 6:
            ip6h = (struct ip6_hdr *)iph;
            lisp_addr_ip_init(&ltuple->src_addr, &ip6h->ip6_src, AF_INET6);
            lisp_addr_ip_init(&ltuple->dst_addr, &ip6h->ip6_dst, AF_INET6);
            /* XXX: assuming no extra headers */
            ltuple->protocol = ip6h->ip6_nxt;
            lbuf_pull(&packet, sizeof(struct ip6_hdr));
            break;
        default:
            OOR_LOG(LDBG_2, "pkt_parse_5_tuple: Not an IP packet!");
            return (BAD);
        }

    if (ltuple->protocol == IPPROTO_UDP) {
        udp = lbuf_data(&packet);
        ltuple->src_port = ntohs(udp->source);
        ltuple->dst_port = ntohs(udp->dest);
    } else if (ltuple->protocol == IPPROTO_TCP) {
        tcp = lbuf_data(&packet);
        ltuple->src_port = ntohs(tcp->source);
        ltuple->dst_port = ntohs(tcp->dest);
    } else {
        /* If protocol is not TCP or UDP, ports of the tuple set to 0 */
        ltuple->src_port = 0;
        ltuple->dst_port = 0;
    }

    ftplt->protocol	= ltuple->protocol;
    ftplt->src_lp	= ltuple->src_port;
	ftplt->src_up	= ltuple->src_port;
	ftplt->dst_lp	= ltuple->dst_port;
	ftplt->dst_up 	= ltuple->dst_port;

    ftplt->src_mlen = mlen();
    ftplt->dst_mlen = mlen();
    ftplt->src_pref = pref_get_network_address(ltuple->src_addr);
    ftplt->dst_pref = pref_get_network_address(ltuple->dst_addr);
    return(iidt);
}

inline int
ftpl_type_write_to_pkt(uint8_t *offset, void *ftpl)
{
    int len;
    uint8_t *cur_ptr = offset;
    ((lcaf_ftpl_hdr_t *)cur_ptr)->afi = htons(LISP_AFI_LCAF);
    ((lcaf_ftpl_hdr_t *)cur_ptr)->rsvd1 = 0;
    ((lcaf_ftpl_hdr_t *)cur_ptr)->flags = 0;
    ((lcaf_ftpl_hdr_t *)cur_ptr)->type = LCAF_IID;
    ((lcaf_ftpl_hdr_t *)cur_ptr)->rsvd2 = 0;
    ((lcaf_ftpl_hdr_t *)cur_ptr)-> = 0;
    offset = CO(offset, sizeof(lcaf_ftpl_hdr_t));
    len = lisp_addr_write(offset, ftpl_type_get_addr(ftpl));
    ((lcaf_ftpl_hdr_t *)cur_ptr)->len = htons(len + sizeof(uint32_t));
    len += sizeof(lcaf_ftpl_hdr_t);

    return(len);
}
