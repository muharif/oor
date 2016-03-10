typedef struct fwd_info_ fwd_info_t;

KHASH_INIT(5tuple, lisp_addr_t *, mdb_t *, 1, lcaf_tuple_hash, lcaf_tuple_cmp)

typedef struct 5tuple {
    khash_t(5tuple) *htable;
    struct ovs_list head_list; /* To order flows */
} 5tuple_t;


typedef struct {
    patricia_tree_t *AF4_ip_db;
    patricia_tree_t *AF6_ip_db;
	int_htable *AF4_iid_db;
    int_htable *AF6_iid_db;
    patricia_tree_t *AF4_mc_db;
    patricia_tree_t *AF6_mc_db;
    5tuple_t	*tpl;
    int n_entries;
} mdb_t;



static int
_add_lcaf_entry(mdb_t *db, void *entry, lcaf_addr_t *lcaf)
{
    switch (lcaf_addr_get_type(lcaf)) {
    case LCAF_IID:
        return (_add_iid_entry(db, entry, lcaf));
    case LCAF_MCAST_INFO:
        return (_add_mc_entry(db, entry, lcaf));
    case LCAF_FTPL:
    	kh_init(5tuple);
    	return (_add_ftpl_entry(db, entry, lcaf));
    default:
        OOR_LOG(LDBG_3, "_add_lcaf_entry: LCAF type %d not supported!",
                lcaf_addr_get_type(lcaf));
    }
    return (BAD);
}

static void *
_del_lcaf_entry(mdb_t *db, lcaf_addr_t *lcaf)
{
    switch (lcaf_addr_get_type(lcaf)) {
    case LCAF_IID:
        return (_rm_iid_entry(db,lcaf));
    case LCAF_MCAST_INFO:
        return (_rm_mc_entry(db,lcaf));
    case LCAF_FTPL:
    	return (_rm_ftpl_entry(db, lcaf));
    default:
        OOR_LOG(LDBG_3, "_del_lcaf_entry: called with unknown LCAF type:%u",
                lcaf_addr_get_type(lcaf));
        break;
    }
    return (NULL);
}

static patricia_node_t *
_find_lcaf_node(mdb_t *db, lcaf_addr_t *lcaf, uint8_t exact)
{
    switch (lcaf_addr_get_type(lcaf)) {
    case LCAF_IID:
        return (_find_iid_node(db,lcaf,exact));
    case LCAF_MCAST_INFO:
        return (pt_find_mc_node(get_mc_pt_from_lcaf(db, lcaf),
                lcaf, exact));
    case LCAF_FTPL:
    	return(mdb_ftpl_lookup(db, lcaf));
    default:
        OOR_LOG(LWRN, "_find_lcaf_node: Unknown LCAF type %u",
                lcaf_addr_get_type(lcaf));
    }
    return (NULL);
}

void
_add_ftpl_entry(mdb_t *db, void *entry, lcaf_addr_t *lcaf)
{
	ftpl = db->tpl;
	khiter_t k;
/*	packet_tuple_t *tpl;

	tpl->src_addr=lcaf_ftpl_get_srcpr(lcaf);
	tpl->dst_addr=lcaf_ftpl_get_dstpr(lcaf);
	tpl->src_port=lcaf_ftpl_get_srcpo(lcaf);
	tpl->dst_port=lcaf_ftpl_get_dstpo(lcaf);
	tpl->protocol=lcaf_ftpl_get_proto(lcaf);*/

    k = kh_put(5tuple, ftpl->htable, lcaf, &ret);
    kh_val(ftpl->htable, k) = entry;
}

void
_rm_ftpl_entry((mdb_t *db, lcaf_addr_t *lcaf)
{
	ftpl = db->tpl;
	khiter_t k;
	/*packet_tuple_t *tpl;

	tpl->src_addr=lcaf_ftpl_get_srcpr(lcaf);
	tpl->dst_addr=lcaf_ftpl_get_dstpr(lcaf);
	tpl->src_port=lcaf_ftpl_get_srcpo(lcaf);
	tpl->dst_port=lcaf_ftpl_get_dstpo(lcaf);
	tpl->protocol=lcaf_ftpl_get_proto(lcaf);*/

    k = kh_get(5tuple,ftpl->htable, lcaf);
    if (k == kh_end(ftpl->htable)){
        return;
    }
    kh_del(5tuple,ftpl->htable,k);
}

/*static void
_rm_ftpl_entry_khiter(ttable_t *tt, khiter_t k)
{
    ttable_node_t *node;

    node = kh_value(tt->htable,k);
    OOR_LOG(LDBG_3,"ttable_remove_with_khiter: Remove tupla: %s ", pkt_tuple_to_char(node->tpl));
    list_remove(&node->list_elt);
    ttable_node_del(node);
    kh_del(ttable,tt->htable,k);
}*/

fwd_info_t *
mdb_ftpl_lookup(mdb_t *db, lcaf_addr_t *lcaf)
{
    khiter_t k;
    double elapsed;

    k = kh_get(5tuple,ftpl->htable, lcaf);
    if (k == kh_end(tt->htable)){
        return (NULL);
    }
    return(kh_value(tt->htable,k));

/*    elapsed = time_elapsed(&tn->ts);
    if (!tn->fi->temporal){
        if (elapsed > TIMEOUT){
            goto expired;
        }
    }else{
        if (elapsed > NEGATIVE_TIMEOUT){
            goto expired;
        }
    }

    list_remove(&tn->list_elt);
    list_push_front(&tt->head_list, &tn->list_elt);

    return (tn->fi);

expired:
    ttable_remove_with_khiter(tt, k);
    return(NULL);
    */
}
