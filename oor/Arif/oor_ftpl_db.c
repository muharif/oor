typedef struct ftpl_node {
    struct ovs_list list_elt;
    packet_tuple_t *tpl;
    struct timespec ts;
} ftpl_node_t;

KHASH_INIT(ttable, packet_tuple_t *, ftpl_node_t *, 1, pkt_tuple_hash, pkt_tuple_cmp)

typedef struct ttable {
    khash_t(ttable) *htable;
    struct ovs_list head_list;
} ttable_t;

typedef struct {
    patricia_tree_t *AF4_ip_db;
    patricia_tree_t *AF6_ip_db;
	int_htable *AF4_iid_db;
    int_htable *AF6_iid_db;
    patricia_tree_t *AF4_mc_db;
    patricia_tree_t *AF6_mc_db;
    ttable_t	*table;
    int n_entries;
} mdb_t;



void
ftpl_table_insert(mdb_t *db, packet_tuple_t *tpl)
{
    khiter_t k;
    ttable_node_t *node;
    struct ovs_list *list_elt;

    if (kh_size(tt->htable) >= MAX_SIZE) {
        OOR_LOG(LDBG_1,"ftpl_table_insert: Max size of forwarding table reached. Removing expired entries");
        removed = 0;
        for (k = kh_begin(db->table-); k != kh_end(db->table->htable); ++k){
            if (!kh_exist(db->table, k)){
                continue;
            }
            if (tnode_expired(kh_value(db->table->htable,k))){
                ftpl_remove_with_khiter(db->table,k);
                removed++;
            }
        }
        if (removed <  OLD_ENTRIES){
            OOR_LOG(LDBG_1,"ftpl_table_insert: Max size of forwarding table reached. Removing older entries");
            to_remove = OLD_ENTRIES - removed;
            for (i = 0 ; i < to_remove ; i++){
                list_elt = list_back(&db->table->head_list);
                node = CONTAINER_OF(list_elt, ttable_node_t, list_elt);
                ttable_remove(db->table, node->tpl);
            }
        }
    }

    node = xzalloc(sizeof(ttable_node_t));
    node->tpl = tpl;
    clock_gettime(CLOCK_MONOTONIC, &node->ts);

    list_init(&node->list_elt);
    list_push_front(&db->table->head_list, &node->list_elt);

    k = kh_put(ttable,db->table->htable,tpl,&ret);
    kh_value(db->table->htable, k) = node;
    OOR_LOG(LDBG_3,"ttable_insert: Inserted tupla: %s ", pkt_tuple_to_char(tpl));
}

static void
ftpl_remove_with_khiter(mdb_t *db, khiter_t k)
{
    ttable_node_t *node;

    node = kh_value(db->table->htable,k);
    list_remove(&node->list_elt);
    ttable_node_del(node);
    kh_del(ttable,db->table->htable,k);
}



void
ttable_remove(ttable_t *tt, packet_tuple_t *tpl)
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
ttable_remove_with_khiter(ttable_t *tt, khiter_t k)
{
    ttable_node_t *node;

    node = kh_value(tt->htable,k);
    OOR_LOG(LDBG_3,"ttable_remove_with_khiter: Remove tupla: %s ", pkt_tuple_to_char(node->tpl));
    list_remove(&node->list_elt);
    ttable_node_del(node);
    kh_del(ttable,tt->htable,k);
}

fwd_info_t *
ttable_lookup(ttable_t *tt, packet_tuple_t *tpl)
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












