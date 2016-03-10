typedef struct fwd_info_ fwd_info_t;

typedef struct ttable_node {
    struct ovs_list list_elt;
    packet_tuple_t *tpl;
    fwd_info_t *fi;
    struct timespec ts;
} ttable_node_t;

KHASH_INIT(ttable, packet_tuple_t *, ttable_node_t *, 1, lcaf_tuple_hash, lcaf_tuple_cmp)

typedef struct ttable {
    khash_t(ttable) *htable;
    struct ovs_list head_list; /* To order flows */
} ttable_t;


typedef struct {
    patricia_tree_t *AF4_ip_db;
    patricia_tree_t *AF6_ip_db;
	int_htable *AF4_iid_db;
    int_htable *AF6_iid_db;
    patricia_tree_t *AF4_mc_db;
    patricia_tree_t *AF6_mc_db;
    ttable1_t	*table;
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

void
_add_ftpl_entry(mdb_t *db, void *entry, lcaf_addr_t *lcaf)
{
    khiter_t k;
    int ret,i,removed,to_remove;
    ttable_node_t *node;
    struct ovs_list *list_elt;

    /* If table is full, lookup and remove expired entries. If it is still
     * full, remove old entries */
    if (kh_size(tt->htable) >= MAX_SIZE) {
        OOR_LOG(LDBG_1,"ttable_insert: Max size of forwarding table reached. Removing expired entries");
        removed = 0;
        for (k = kh_begin(tt->htable); k != kh_end(tt->htable); ++k){
            if (!kh_exist(tt->htable, k)){
                continue;
            }
            if (tnode_expired(kh_value(tt->htable,k))){
            	_rm_ftpl_entry_khiter(tt,k);
                removed++;
            }
        }
        if (removed <  OLD_ENTRIES){
            OOR_LOG(LDBG_1,"ttable_insert: Max size of forwarding table reached. Removing older entries");
            to_remove = OLD_ENTRIES - removed;
            for (i = 0 ; i < to_remove ; i++){
                list_elt = list_back(&tt->head_list);
                node = CONTAINER_OF(list_elt, ttable_node_t, list_elt);
                _rm_ftpl_entry(tt, node->tpl);
            }
        }
    }

    node = xzalloc(sizeof(ttable_node_t));
    node->fi = fi;
    node->tpl = tpl;
    clock_gettime(CLOCK_MONOTONIC, &node->ts);

    list_init(&node->list_elt);
    list_push_front(&tt->head_list, &node->list_elt);

    k = kh_put(ttable,tt->htable,tpl,&ret);
    kh_value(tt->htable, k) = node;
    OOR_LOG(LDBG_3,"ttable_insert: Inserted tupla: %s ", pkt_tuple_to_char(tpl));
}

void
_rm_ftpl_entry(ttable_t *tt, packet_tuple_t *tpl)
{
    khiter_t k;
    ttable_node_t *tn;

    k = kh_get(ttable,tt->htable, tpl);
    if (k == kh_end(tt->htable)){
        return;
    }
    tn = kh_value(tt->htable,k);
    OOR_LOG(LDBG_3,"ttable_remove: Remove tupla: %s ", pkt_tuple_to_char(tn->tpl));
    list_remove(&tn->list_elt);
    ttable_node_del(tn);
    kh_del(ttable,tt->htable,k);
}

static void
_rm_ftpl_entry_khiter(ttable_t *tt, khiter_t k)
{
    ttable_node_t *node;

    node = kh_value(tt->htable,k);
    OOR_LOG(LDBG_3,"ttable_remove_with_khiter: Remove tupla: %s ", pkt_tuple_to_char(node->tpl));
    list_remove(&node->list_elt);
    ttable_node_del(node);
    kh_del(ttable,tt->htable,k);
}

fwd_info_t *
mdb_ftpl_lookup(ttable_t *tt, packet_tuple_t *tpl)
{
    ttable_node_t *tn;
    khiter_t k;
    double elapsed;

    k = kh_get(ttable,tt->htable, tpl);
    if (k == kh_end(tt->htable)){
        return (NULL);
    }
    tn = kh_value(tt->htable,k);

    elapsed = time_elapsed(&tn->ts);
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
}
