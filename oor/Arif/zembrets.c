uint32_t
lcaf_tuple_hash(lisp_addr_t *lsp)
{
    lcaf_addr_t *lcaf;
    packet_tuple_t *tuple
    int hash = 0;
    int len = 0;
    lcaf = lisp_addr_get_lcaf(lsp);
    tuple->src_addr=lcaf_ftpl_get_srcpr(lcaf);
    tuple->dst_addr=lcaf_ftpl_get_dstpr(lcaf);
    tuple->src_port=lcaf_ftpl_get_srcpo(lcaf);
    tuple->dst_port=lcaf_ftpl_get_dstpo(lcaf);
    tuple->protocol=lcaf_ftpl_get_proto(lcaf);
    int port = tuple->src_port;
    uint32_t *tuples = NULL;

    port = port + ((int)tuple->dst_port << 16);
    switch (lisp_addr_ip_afi(&tuple->src_pref)){
    case AF_INET:
        /* 1 integer src_addr
         * + 1 integer dst_adr
         * + 1 integer (ports)
         * + 1 integer protocol
         * + 1 iid*/
        len = 5;
        tuples = xmalloc(len * sizeof(uint32_t));
        lisp_addr_copy_to(&tuples[0], &tuple->src_addr);
        lisp_addr_copy_to(&tuples[1], &tuple->dst_addr);
        tuples[2] = port;
        tuples[3] = tuple->protocol;
        tuples[4] = tuple->iid;
        break;
    case AF_INET6:
        /* 4 integer src_addr
         * + 4 integer dst_adr
         * + 1 integer (ports)
         * + 1 integer protocol
         * + 1 iid */
        len = 11;
        tuples = xmalloc(len * sizeof(uint32_t));
        lisp_addr_copy_to(&tuples[0], &tuple->src_addr);
        lisp_addr_copy_to(&tuples[4], &tuple->dst_addr);
        tuples[8] = port;
        tuples[9] = tuple->protocol;
        tuples[10] = tuple->iid;
        break;
    }

    /* XXX: why 2013 used as initial value? */
    hash = hashword(tuples, len, 2013);
    free(tuples);
    return (hash);

}

int
lisp_tuple_cmp(lisp_addr_t *lsp1, lisp_addr_t *lsp2)
{
    lcaf_addr_t *lcaf1;
    lcaf_addr_t *lcaf2;
    packet_tuple_t *t1
	packet_tuple_t *t2
    int hash = 0;
    int len = 0;
    lcaf1 = lisp_addr_get_lcaf(lsp1);
    lcaf2 = lisp_addr_get_lcaf(lsp2);
    t1 = ftpl_type_set(lcaf1->src_lp, lcaf1->dst_lp,lcaf1->protocol, lcaf1->src_pref,lcaf1->dst_pref);
    t2 = ftpl_type_set(lcaf2->src_lp, lcaf2->dst_lp,lcaf2->protocol, lcaf2->src_pref,lcaf2->dst_pref);

	t1->src_addr=lcaf_ftpl_get_srcpr(lcaf1);
	t1->dst_addr=lcaf_ftpl_get_dstpr(lcaf1);
	t1->src_port=lcaf_ftpl_get_srcpo(lcaf1);
	t1->dst_port=lcaf_ftpl_get_dstpo(lcaf1);
	t1->protocol=lcaf_ftpl_get_proto(lcaf1);

	t2->src_addr=lcaf_ftpl_get_srcpr(lcaf2);
	t2->dst_addr=lcaf_ftpl_get_dstpr(lcaf2);
	t2->src_port=lcaf_ftpl_get_srcpo(lcaf2);
	t2->dst_port=lcaf_ftpl_get_dstpo(lcaf2);
	t2->protocol=lcaf_ftpl_get_proto(lcaf2);

	return(t1->src_port == t2->src_port
           && t1->dst_port == t2->dst_port
           && (lisp_addr_cmp(&t1->src_addr, &t2->src_addr) == 0)
           && (lisp_addr_cmp(&t1->dst_addr, &t2->dst_addr) == 0)
           && t1->iid == t2->iid);
}


KHASH_INIT(5tuple, lisp_addr_t *, mcache_entry_t *, 1, lcaf_tuple_hash, lcaf_tuple_cmp);


typedef struct ftuple {
    khash_t(5tuple) *htable;
    struct ovs_list head_list; /* To order flows */
} ftuple_t;


static void *
_add_ftpl_entry(mdb_t *db, void *entry, lcaf_addr_t *lcaf)
{
	ftuple_t *ftpl;
	ftpl = db->tpl;
	khiter_t k;

    k = kh_put(5tuple, ftpl->htable, lcaf, &ret);
    kh_val(ftpl->htable, k) = entry;
    return(GOOD);
}

static void *
_rm_ftpl_entry(mdb_t *db, lcaf_addr_t *lcaf)
{
	ftuple_t *ftpl;
	ftpl = db->tpl;
	khiter_t k;

    k = kh_get(5tuple,ftpl->htable, lcaf);
    if (k == kh_end(ftpl->htable)){
        return(GOOD);
    }
    return(kh_del(5tuple,ftpl->htable,k));
}
