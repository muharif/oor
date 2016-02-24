
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

inline ftpl_t            *lcaf_addr_get_ftpl(lcaf_addr_t *lcaf);
inline int              lcaf_addr_is_ftpl(lcaf_addr_t *lcaf);

inline iid_t *
lcaf_addr_get_ftpl(lcaf_addr_t *lcaf)
{
    assert(lcaf);
    return((ftpl_t *)lcaf_addr_get_addr(lcaf));
}

inline int
lcaf_addr_is_ftpl(lcaf_addr_t *lcaf)
{
    if (lcaf_addr_get_type(lcaf) == LCAF_FTPL)
        return(TRUE);
    else
        return(FALSE);
}


inline ftpl_t                *ftpl_type_new();
ftpl_t *                     ftpl_type_new_init(int ftpl, lisp_addr_t *addr, uint8_t mlen);
inline void                 ftpl_type_del(void *ftpl);
inline uint32_t             ftpl_type_get_ftpl(ftpl_t *ftpl);
inline lisp_addr_t          *ftpl_type_get_addr(void *ftpl);
inline void                 ftpl_type_set_ftpl(ftpl_t *addr, uint32_t ftpl);
inline void                 ftpl_type_set_addr(ftpl_t *addr, lisp_addr_t *ftpladdr);
inline void                 ftpl_type_set_mlen(ftpl_t *addr, uint8_t mlen);
inline int                  ftpl_type_cmp(void *ftpl1, void *ftpl2);
int                         ftpl_type_get_size_to_write(void *ftpl);
inline int                  ftpl_type_write_to_pkt(uint8_t *offset, void *ftpl);
int                         ftpl_type_parse(uint8_t *offset, void **ftpl);
char                        *ftpl_type_to_char(void *ftpl);
void                        ftpl_type_copy(void **dst, void *src);
ftpl_t                       *ftpl_type_init(int ftpl, lisp_addr_t *addr, uint8_t mlen);
lisp_addr_t *				ftpl_type_get_ip_addr(void *ftpl);
lisp_addr_t *               ftpl_type_get_ip_pref_addr(void *ftpl);
void                        lcaf_ftpl_init(lcaf_addr_t *ftpladdr, int ftpl, lisp_addr_t *addr, uint8_t mlen);
inline int                  lisp_addr_is_ftpl(lisp_addr_t *addr);
lisp_addr_t *               lisp_addr_new_init_ftpl(int ftpl, lisp_addr_t *addr, uint8_t mlen);



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
ftpl_type_new_init()
{
    ftpl_t *ftplt = iid_type_new();
    ftplt->src_lp	= 0;
	ftplt->src_up	= 0;
	ftplt->dst_lp	= 0;
	ftplt->dst_up 	= 0;
	ftplt->protocol	= 0;
    ftplt->src_mlen = 0;
    ftplt->dst_mlen = 0;
    ftplt->src_pref = 0;
    ftplt->dst_pref = 0;
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
