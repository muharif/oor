/*
 * tpl type functions
 */

inline lisp_addr_t 		*lcaf_ftpl_get_srcpref(lcaf_addr_t *ftpl);
inline lisp_addr_t 		*lcaf_ftpl_get_dstpref(lcaf_addr_t *ftpl);
inline uint16_t			lcaf_ftpl_get_srclp(lcaf_addr_t *ftpl);
inline uint16_t			lcaf_ftpl_get_srcup(lcaf_addr_t *ftpl);
inline uint16_t			lcaf_ftpl_get_dstlp(lcaf_addr_t *ftpl);
inline uint16_t			lcaf_ftpl_get_dstup(lcaf_addr_t *ftpl);
inline uint32_t			lcaf_ftpl_get_proto(lcaf_addr_t *ftpl);
inline uint16_t			lcaf_ftpl_get_src_mlen(lcaf_addr_t *ftpl);
inline uint16_t			lcaf_ftpl_get_dst_mlen(lcaf_addr_t *ftpl);
inline ftpl_t 			*ftpl_type_new();
inline void				ftpl_type_del(void *ftpl);
inline void				ftpl_type_set_mlen(ftpl_t *ftpl, uint16_t mlen);
inline void				ftpl_type_set_port(ftpl_t *ftpl, uint16_t port);
inline void				ftpl_type_set_proto(ftpl_t *ftpl, uint32_t proto);
inline void				ftpl_type_set_srcpref(void *ftpl, lisp_addr_t *srcpref);
inline void				ftpl_type_set_dstpref(ftpl_t *ftpl, lisp_addr_t *dstpref);
inline void				ftpl_type_set(ftpl_t *dst, lisp_addr_t *src_pref, lisp_addr_t *dst_pref, uint16_t port, uint32_t proto, uint16_t mlen);
ftpl_t *				ftpl_type_init(lisp_addr_t *src_pref, lisp_addr_t *dst_pref, uint16_t port, uint32_t proto, uint16_t mlen);
inline lisp_addr_t 		*ftpl_type_get_srcpref(ftpl_t *ftpl);
inline lisp_addr_t 		*ftpl_type_get_dstpref(ftpl_t *ftpl);
inline uint16_t			ftpl_type_get_srclp(ftpl_t *ftpl);
inline uint16_t			ftpl_type_get_srcup(ftpl_t *ftpl);
inline uint16_t			ftpl_type_get_dstlp(ftpl_t *ftpl);
inline uint16_t			ftpl_type_get_dstup(ftpl_t *ftpl);
inline uint32_t			ftpl_type_get_proto(ftpl_t *ftpl);
inline uint16_t			ftpl_type_get_src_mlen(ftpl_t *ftpl);
inline uint16_t			ftpl_type_get_dst_mlen(ftpl_t *ftpl);
char 					*ftpl_type_to_char(void *ftpl);
int						ftpl_type_get_size_to_write(void *ftpl);


inline ftpl_t *
lcaf_addr_get_ftpl(lcaf_addr_t *lcaf)
{
    assert(lcaf);
    return((ftpl_t *)lcaf_addr_get_addr(lcaf));
}

/*
 * ftp_t functions
 */

inline lisp_addr_t *
lcaf_ftpl_get_srcpref(lcaf_addr_t *ftpl)
{
    assert(ftpl);
    if (lcaf_addr_get_type(ftpl) != LCAF_FTPL)
        return(NULL);
    return(ftpl_type_get_srcpref(lcaf_addr_get_ftpl(ftpl)));
}

inline lisp_addr_t *
lcaf_ftpl_get_dstpref(lcaf_addr_t *ftpl)
{
    assert(ftpl);
    if (lcaf_addr_get_type(ftpl) != LCAF_FTPL)
        return(NULL);
    return(ftpl_type_get_dstpref(lcaf_addr_get_ftpl(ftpl)));
}

inline uint16_t
lcaf_ftpl_get_srclp(lcaf_addr_t *ftpl)
{
    assert(ftpl);
    return(ftpl_type_get_srclp(lcaf_addr_get_ftpl(ftpl)));
}

inline uint16_t
lcaf_ftpl_get_srcup(lcaf_addr_t *ftpl)
{
    assert(ftpl);
    return(ftpl_type_get_srcup(lcaf_addr_get_ftpl(ftpl)));
}


inline uint16_t
lcaf_ftpl_get_dstlp(lcaf_addr_t *ftpl)
{
    assert(ftpl);
    return(ftpl_type_get_dstlp(lcaf_addr_get_ftpl(ftpl)));
}

inline uint16_t
lcaf_ftpl_get_dstup(lcaf_addr_t *ftpl)
{
    assert(ftpl);
    return(ftpl_type_get_dstup(lcaf_addr_get_ftpl(ftpl)));
}

inline uint32_t
lcaf_ftpl_get_proto(lcaf_addr_t *ftpl)
{
    assert(ftpl);
    return(ftpl_type_get_proto(lcaf_addr_get_ftpl(ftpl)));
}

inline uint16_t
lcaf_ftpl_get_src_mlen(lcaf_addr_t *ftpl)
{
    assert(ftpl);
    return(ftpl_type_get_src_mlen(ftpl->addr));
}

inline uint16_t
lcaf_ftpl_get_dst_mlen(lcaf_addr_t *ftpl)
{
    assert(ftpl);
    return(ftpl_type_get_dst_mlen(ftpl->addr));
}

/* these shouldn't be called from outside */

inline ftpl_t *
ftpl_type_new()
{
    ftpl_t *ftpl = calloc(1, sizeof(ftpl_t));
    ftpl->src_pref = lisp_addr_new();
    ftpl->dst_pref = lisp_addr_new();
    return(ftpl);
}

inline void
ftpl_type_del(void *ftpl)
{
    lisp_addr_del(ftpl_type_get_srcpref(ftpl));
    lisp_addr_del(ftpl_type_get_dstpref(ftpl));

    free(ftpl);
}

inline void
ftpl_type_set_src_mlen(ftpl_t *ftpl, uint16_t mlen)
{
    assert(ftpl);
    ftpl->src_mlen = mlen;
}

inline void
ftpl_type_set_dst_mlen(ftpl_t *ftpl, uint16_t mlen)
{
    assert(ftpl);
    ftpl->dst_mlen = mlen;
}

inline void
ftpl_type_set_src_port(ftpl_t *ftpl, uint16_t port)
{
    assert(ftpl);
    ftpl->src_lp = port;
    ftpl->src_up = port;
}

inline void
ftpl_type_set_dst_port(ftpl_t *ftpl, uint16_t port)
{
    assert(ftpl);
    ftpl->dst_lp = port;
    ftpl->dst_up = port;
}

inline void
ftpl_type_set_proto(ftpl_t *ftpl, uint32_t proto)
{
    assert(ftpl);
    ftpl->protocol = proto;
}

inline void
ftpl_type_set_srcpref(void *ftpl, lisp_addr_t *srcpref)
{
    assert(ftpl);
    assert(srcpref);
    lisp_addr_copy(ftpl_type_get_srcpref(ftpl), srcpref);
}

inline void
ftpl_type_set_dstpref(ftpl_t *ftpl, lisp_addr_t *dstpref)
{
    assert(ftpl);
    assert(dstpref);
    lisp_addr_copy(ftpl_type_get_dstpref(ftpl), dstpref);
}

inline void
ftpl_type_set(ftpl_t *dst, lisp_addr_t *src_pref, lisp_addr_t *dst_pref, uint16_t src_port, uint16_t dst_port, uint32_t proto, uint16_t src_mlen, uint16_t dst_mlen)
{
    assert(src_pref);
    assert(dst_pref);
    assert(dst);
    ftpl_type_set_srcpref(dst, src_pref);
    ftpl_type_set_dstpref(dst, dst_pref);
    ftpl_type_set_src_port(dst, src_port);
    ftpl_type_set_dst_port(dst, dst_port);
    ftpl_type_set_proto(dst, proto);
    ftpl_type_set_src_mlen(dst, src_mlen);
    ftpl_type_set_dst_mlen(dst, dst_mlen);
}

/**
 * mc_addr_init - makes an mc_addr_t from the parameters passed
 * @ src: source ip
 * @ grp: group ip
 * @ splen: source prefix length
 * @ gplen: group prefix length
 * @ iid: iid of the address
 */

ftpl_t *
ftpl_type_init(lisp_addr_t *src_pref, lisp_addr_t *dst_pref, uint16_t src_port, uint16_t dst_port, uint32_t proto, uint16_t src_mlen, uint16_t dst_mlen)
{
    ftpl_t *ftpl;

    assert(src_pref);
    assert(dst_pref);

    ftpl = ftpl_type_new();
    lisp_addr_copy(ftpl_type_get_srcpref(ftpl), src_pref);
    lisp_addr_copy(ftpl_type_get_dstpref(ftpl), dst_pref);
    ftpl_type_set_src_port(ftpl, src_port);
    ftpl_type_set_dst_port(ftpl, dst_port);
    ftpl_type_set_proto(ftpl, proto);
    ftpl_type_set_src_mlen(ftpl, src_mlen);
    ftpl_type_set_dst_mlen(ftpl, dst_mlen);
    return(ftpl);
}

inline lisp_addr_t
*ftpl_type_get_srcpref(ftpl_t *ftpl)
{
    assert(ftpl);
    return(ftpl->src_pref);
}

inline lisp_addr_t
*ftpl_type_get_dstpref(ftpl_t *ftpl)
{
    assert(ftpl);
    return(ftpl->dst_pref);
}

inline uint16_t
ftpl_type_get_srclp(ftpl_t *ftpl)
{
    assert(ftpl);
    return(ftpl->src_lp);
}

inline uint16_t
ftpl_type_get_srcup(ftpl_t *ftpl)
{
    assert(ftpl);
    return(ftpl->src_up);
}

inline uint16_t
ftpl_type_get_dstlp(ftpl_t *ftpl)
{
    assert(ftpl);
    return(ftpl->dst_lp);
}

inline uint16_t
ftpl_type_get_dstup(ftpl_t *ftpl)
{
    assert(ftpl);
    return(ftpl->dst_up);
}

inline uint32_t
ftpl_type_get_proto(ftpl_t *ftpl)
{
    assert(ftpl);
    return(ftpl->protocol);
}

inline uint16_t
ftpl_type_get_src_mlen(ftpl_t *ftpl)
{
    assert(ftpl);
    return(ftpl->src_mlen);
}

inline uint16_t
ftpl_type_get_dst_mlen(ftpl_t *ftpl)
{
    assert(ftpl);
    return(ftpl->dst_mlen);
}

/* set functions common to all types */

char *
ftpl_type_to_char(void *ftpl)
{
    static char buf[10][INET6_ADDRSTRLEN*2+4];
    static unsigned int i   = 0;

    i++;
    i = i % 10;
    *buf[i] = '\0';
    sprintf(buf[i], "(%s/%d,%s/%d)",
            lisp_addr_to_char(ftpl_type_get_srcpref((ftpl_t *)ftpl)),
            ftpl_type_get_src_mlen((ftpl_t *)ftpl),
            lisp_addr_to_char(ftpl_type_get_dstpref((ftpl_t *)ftpl)),
            ftpl_type_get_dst_mlen((ftpl_t *)ftpl));
    return(buf[i]);
}

int
ftpl_type_get_size_to_write(void *ftpl)
{
    return( sizeof(lcaf_ftpl_hdr_t));
}

inline int
ftpl_type_write_to_pkt(uint8_t *offset, void *ftpl)
{
    int     lena1 = 0, lena2 = 0;
    uint8_t *cur_ptr = NULL;
    ((lcaf_ftpl_hdr_t *)offset)->afi = htons(LISP_AFI_LCAF);
    ((lcaf_ftpl_hdr_t *)offset)->rsvd1 = 0;
    ((lcaf_ftpl_hdr_t *)offset)->flags = 0;
    ((lcaf_ftpl_hdr_t *)offset)->type = LCAF_FTPL;
    ((lcaf_ftpl_hdr_t *)offset)->rsvd2 = 0;
    ((lcaf_ftpl_hdr_t *)offset)->reserved = 0;
    ((lcaf_ftpl_hdr_t *)offset)->src_lp=ftpl_type_get_srclp(ftpl);
    ((lcaf_ftpl_hdr_t *)offset)->src_up=ftpl_type_get_srcup(ftpl);
    ((lcaf_ftpl_hdr_t *)offset)->dst_lp=ftpl_type_get_dstlp(ftpl);
    ((lcaf_ftpl_hdr_t *)offset)->dst_up=ftpl_type_get_dstup(ftpl);
    ((lcaf_ftpl_hdr_t *)offset)->protocol=ftpl_type_get_proto(ftpl);
    ((lcaf_ftpl_hdr_t *)offset)->src_mlen=ftpl_type_get_src_mlen(ftpl);
    ((lcaf_ftpl_hdr_t *)offset)->dst_mlen=ftpl_type_get_dst_mlen(ftpl);
    cur_ptr = CO(offset, sizeof(lcaf_ftpl_hdr_t));
    cur_ptr = CO(cur_ptr, (lena1 = lisp_addr_write(cur_ptr, ftpl_type_get_srcpref(ftpl))));
    lena2 = lisp_addr_write(cur_ptr, ftpl_type_get_dstpref(ftpl));
    ((lcaf_ftpl_hdr_t *)offset)->len = htons(lena1+lena2+8*sizeof(uint8_t));
    return(sizeof(lcaf_ftpl_hdr_t)+lena1+lena2);
}

int
ftpl_type_parse(uint8_t *offset, void **ftpl)
{
    int srclen, dstlen;
    srclen = dstlen =0;

    *ftpl = ftpl_type_new();

    ftpl_type_set_src_port(*ftpl, ((lcaf_ftpl_hdr_t *)offset)->src_lp);
    ftpl_type_set_dst_port(*ftpl, ((lcaf_ftpl_hdr_t *)offset)->dst_lp);
    ftpl_type_set_proto(*ftpl, ((lcaf_ftpl_hdr_t *)offset)->protocol);
    ftpl_type_set_src_mlen(*ftpl, ((lcaf_ftpl_hdr_t *)offset)->src_mlen);
    ftpl_type_set_dst_mlen(*ftpl, ((lcaf_ftpl_hdr_t *)offset)->dst_mlen);

    offset = CO(offset, sizeof(lcaf_ftpl_hdr_t));
    srclen = lisp_addr_parse(offset, ftpl_type_get_srcpref(*ftpl));
    offset = CO(offset, srclen);
    dstlen = lisp_addr_parse(offset, ftpl_type_get_dstpref(*ftpl));
    return(sizeof(lcaf_ftpl_hdr_t) + srclen + dstlen);

}

inline void
ftpl_type_copy(void **dst, void *src)
{
    if (!(*dst))
        *dst = ftpl_type_new();
    mc_type_set_iid(*dst, mc_type_get_iid(src));
    mc_type_set_src_plen(*dst, mc_type_get_src_plen(src));
    mc_type_set_grp_plen(*dst, mc_type_get_grp_plen(src));
    lisp_addr_copy(mc_type_get_src(*dst), mc_type_get_src(src));
    lisp_addr_copy(mc_type_get_grp(*dst), mc_type_get_grp(src));
}

inline int
mc_type_cmp(void *mc1, void *mc2)
{
    if (    (mc_type_get_iid(mc1) != mc_type_get_iid(mc2)) ||
            (mc_type_get_src_plen(mc1) != mc_type_get_src_plen(mc2)) ||
            (mc_type_get_grp_plen(mc1) != mc_type_get_grp_plen(mc2)))
        return(-1);

    /* XXX: rushed implementation
     * (S, G) comparison
     * First compare S and then G*/
    int res = lisp_addr_cmp(mc_type_get_src(mc1), mc_type_get_src(mc2));
    if (res == 0)
        return(lisp_addr_cmp(mc_type_get_grp(mc1), mc_type_get_grp(mc2)));
    else
        return(res);

}

inline void
ftpl_type_copy(void **dst, void *src)
{
    if (!(*dst))
        *dst = mc_type_new();

    ftpl_type_set_src_port(*dst, ftpl_type_get_srclp(src));
    ftpl_type_set_dst_port(*dst, ftpl_type_get_dstlp(src));
    ftpl_type_set_proto(*dst, ftpl_type_get_proto(src));
    ftpl_type_set_src_mlen(*dst, ftpl_type_get_src_mlen(src));
    ftpl_type_set_dst_mlen(*dst, ftpl_type_get_dst_mlen(src));
    lisp_addr_copy(ftpl_type_get_srcpref(*dst), ftpl_type_get_srcpref(src));
    lisp_addr_copy(ftpl_type_get_dstpref(*dst), ftpl_type_get_dstpref(src));
}

inline int
ftpl_type_cmp(void *ftpl1, void *ftpl2)
{
    if (    (ftpl_type_get_srclp(ftpl1) != ftpl_type_get_srclp(ftpl2)) ||
            (ftpl_type_get_dstlp(ftpl1) != ftpl_type_get_dstlp(ftpl2)) ||
            (ftpl_type_get_proto(ftpl1) != ftpl_type_get_proto(ftpl2)) ||
			(ftpl_type_get_src_mlen(ftpl1) != ftpl_type_get_src_mlen(ftpl2)) ||
			(ftpl_type_get_dst_mlen(ftpl1) != ftpl_type_get_dst_mlen(ftpl2)))
        return(-1);


    int res = lisp_addr_cmp(ftpl_type_get_srcpref(ftpl1), ftpl_type_get_srcpref(ftpl2));
    if (res == 0)
        return(lisp_addr_cmp(ftpl_type_get_dstpref(ftpl1), ftpl_type_get_dstpref(ftpl2)));
    else
        return(res);
}

int
lcaf_addr_set_ftpl(lcaf_addr_t *lcaf, lisp_addr_t *src_pref, lisp_addr_t *dst_pref,
		uint16_t src_port, uint16_t dst_port, uint32_t proto, uint16_t src_mlen, uint16_t dst_mlen)
{
    ftpl_t            *ftpl;

    if (get_addr_(lcaf)) {
        lcaf_addr_del_addr(lcaf);
    }

    mc = mc_type_init(src_pref, dst_pref, src_port, dst_port, proto, src_mlen, dst_mlen);
    lcaf_addr_set_type(lcaf, LCAF_FTPL);
    lcaf_addr_set_addr(lcaf, ftpl);
    return(GOOD);
}

lisp_addr_t *
lisp_addr_build_ftpl(lisp_addr_t *src_pref, lisp_addr_t *dst_pref, uint16_t src_port,
		uint16_t dst_port, uint32_t proto, uint16_t src_mlen, uint16_t dst_mlen)
{
    lisp_addr_t     *ftplid;

    ftplid = lisp_addr_new_lafi(LM_AFI_LCAF);
    lcaf_addr_set_ftpl(lisp_addr_get_lcaf(ftplid), src_pref, dst_pref, src_port, dst_port, proto ,src_mlen, dst_mlen);
    return(ftplid);
}

inline int
lisp_addr_is_ftplinfo(lisp_addr_t *addr)
{
    return(lisp_addr_lafi(addr) == LM_AFI_LCAF && lisp_addr_lcaf_type(addr) == LCAF_FTPL);
}

/* Function that builds mc packets from packets on the wire. */
int
lcaf_addr_set_mc(lcaf_addr_t *lcaf, lisp_addr_t *src, lisp_addr_t *grp,
        uint8_t splen, uint8_t gplen, uint32_t iid)
{
    mc_t            *mc;

    if (get_addr_(lcaf)) {
        lcaf_addr_del_addr(lcaf);
    }

    mc = mc_type_init(src, grp, splen, gplen, iid);
    lcaf_addr_set_type(lcaf, LCAF_MCAST_INFO);
    lcaf_addr_set_addr(lcaf, mc);
    return(GOOD);
}

lisp_addr_t *
lisp_addr_build_mc(lisp_addr_t *src, lisp_addr_t *grp)
{
    lisp_addr_t     *mceid;
    uint8_t         mlen;

    mlen = (lisp_addr_ip_afi(src) == AF_INET) ? 32 : 128;
    mceid = lisp_addr_new_lafi(LM_AFI_LCAF);
    lcaf_addr_set_mc(lisp_addr_get_lcaf(mceid), src, grp, mlen, mlen, 0);
    return(mceid);
}

inline int
lisp_addr_is_mcinfo(lisp_addr_t *addr)
{
    return(lisp_addr_lafi(addr) == LM_AFI_LCAF && lisp_addr_lcaf_type(addr) == LCAF_MCAST_INFO);
}






