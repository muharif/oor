
typedef struct map_cache_entry_ {
    uint8_t how_learned;

    mapping_t *mapping;

    /* mapping validity information */

    /* TRUE if we have received a map reply for this entry */
    uint8_t active;
    uint8_t active_witin_period;
    time_t timestamp;

    /* Routing info */
    void *                  routing_info;
    routing_info_del_fct    routing_inf_del;

    glist_t *timers_lst;

    /* EID that requested the mapping. Helps with timers */
    lisp_addr_t *requester;
} mcache_entry_t;

KHASH_INIT(ttable1, packet_tuple_t *, mcache_entry_t *, 1, pkt_tuple_hash, pkt_tuple_cmp)

typedef struct ttable1 {
    khash_t(ttable1) *htable;
    struct ovs_list head_list;
} ttable1_t;

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

static double
time_elapsed(struct timespec *time_node)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return(time_diff(time_node, &now));
}

static void
ttable1_node_del(mcache_entry_t *mcet)
{
    pkt_tuple_del(mcet->mapping);
    //fwd_info_del(tn->fi,(fwd_info_data_del)fwd_entry_del);
    free(tn);
}

void
ttable1_init(ttable1_t *tt)
{
    tt->htable =  kh_init(ttable);
    list_init(&tt->head_list);
}

void
ttable1_uninit(ttable1_t *tt)
{
    khiter_t k;

    for (k = kh_begin(tt->htable); k != kh_end(tt->htable); ++k){
        if (kh_exist(tt->htable, k)){
            ttable1_node_del(kh_value(tt->htable,k));
        }
    }
    kh_destroy(ttable, tt->htable);
}

ttable1_t *
ttable1_create()
{
   ttable1_t *tt = xzalloc(sizeof(ttable_t));
   ttable1_init(tt);
   return(tt);
}

void
ttable1_destroy(ttable1_t *tt)
{
    ttable1_uninit(tt);
    free(tt);
}

/*
static int
tnode_expired(ttable_node_t *tn)
{
    return(time_elapsed(&tn->ts) > TIMEOUT);
}
*/

void
ttable1_insert(ttable1_t *tt, packet_tuple_t *tpl, fwd_info_t *fi)
{
    khiter_t k;
    int ret,i,removed,to_remove;
    mcache_entry_t *mcet;

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
                ttable_remove_with_khiter(tt,k);
                removed++;
            }
        }
        if (removed <  OLD_ENTRIES){
            OOR_LOG(LDBG_1,"ttable_insert: Max size of forwarding table reached. Removing older entries");
            to_remove = OLD_ENTRIES - removed;
            for (i = 0 ; i < to_remove ; i++){
                list_elt = list_back(&tt->head_list);
                node = CONTAINER_OF(list_elt, ttable_node_t, list_elt);
                ttable_remove(tt, node->tpl);
            }
        }
    }

    mcet = xzalloc(sizeof(mcache_entry_t));
    mcet->tpl = tpl;

    mcache_entry_new();
    mcache_entry_init(mcet, tpl);

    k = kh_put(ttable1,tt->htable,tpl,&ret);
    kh_value(tt->htable, k) = node;
    OOR_LOG(LDBG_3,"ttable_insert: Inserted tupla: %s ", pkt_tuple_to_char(tpl));
}

void
ttable1_remove(ttable1_t *tt, packet_tuple_t *tpl)
{
    khiter_t k;
    mcache_entry_t *mcet;

    k = kh_get(ttable1,tt->htable, tpl);
    if (k == kh_end(tt->htable)){
        return;
    }
    tn = kh_value(tt->htable,k);
    OOR_LOG(LDBG_3,"ttable_remove: Remove tupla: %s ", pkt_tuple_to_char(tn->tpl));
    mcache_del(mcet);
    kh_del(ttable,tt->htable,k);
}

static void
ttable_remove_with_khiter(ttable_t *tt, khiter_t k)
{
    mcache_entry_t *mcet;

    node = kh_value(tt->htable,k);
    OOR_LOG(LDBG_3,"ttable_remove_with_khiter: Remove tupla: %s ", pkt_tuple_to_char(node->tpl));
    mcache_del(mcet);
    kh_del(ttable1,tt->htable,k);
}

void
ttable1_lookup(ttable1_t *tt, packet_tuple_t *tpl)
{
    mcache_entry_t *mcet;
    khiter_t k;
    double elapsed;

    k = kh_get(ttable1,tt->htable, tpl);
    if (k == kh_end(tt->htable)){
        return (NULL);
    }
    mcet = kh_value(tt->htable,k);

    elapsed = time_elapsed(&mcet->timestamp);
    if (mcet){
        if (elapsed > TIMEOUT){
            goto expired;
        }
    }else{
        if (elapsed > NEGATIVE_TIMEOUT){
            goto expired;
        }
    }

   /* list_remove(&tn->list_elt);
    list_push_front(&tt->head_list, &tn->list_elt);


    return (tn->fi);*/

expired:
    ttable1_remove_with_khiter(tt, k);
    return(NULL);
}

