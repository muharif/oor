/*
 *
 * Copyright (C) 2011, 2015 Cisco Systems, Inc.
 * Copyright (C) 2015 CBA research group, Technical University of Catalonia.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/*
 * This defines a mappings database (mdb) that relies on patricia tries and hash tables
 * to store IP and LCAF based EIDs. Among the supported LCAFs are multicast of type (S,G) and IID.
 * It is used to implement both the mappings cache and the local mapping db.
 */

#ifndef MAPPING_DB_H_
#define MAPPING_DB_H_

#include "int_table.h"
#include "../elibs/patricia/patricia.h"
#include "../liblisp/lisp_address.h"
#include "../elibs/khash/khash.h"

#define NOT_EXACT 0
#define EXACT 1



/*
 *  Patricia tree based databases
 *  for IP/IP-prefix and multicast addresses
 */

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

typedef struct {
    patricia_tree_t *AF4_ip_db;
    patricia_tree_t *AF6_ip_db;
    int_htable *AF4_iid_db;
    int_htable *AF6_iid_db;
    patricia_tree_t *AF4_mc_db;
    patricia_tree_t *AF6_mc_db;
    ftuple_t *tpl;
    int n_entries;
} mdb_t;


typedef void (*mdb_del_fct)(void *);

mdb_t *mdb_new();
void mdb_del(mdb_t *db, mdb_del_fct del_fct);
int mdb_add_entry(mdb_t *db, lisp_addr_t *addr, void *data);
void *mdb_remove_entry(mdb_t *db, lisp_addr_t *laddr);
void *mdb_lookup_entry(mdb_t *db, lisp_addr_t *laddr);
void *mdb_lookup_entry_exact(mdb_t *db, lisp_addr_t *laddr);
inline int mdb_n_entries(mdb_t *);

patricia_tree_t *_get_local_db_for_lcaf_addr(mdb_t *db, lcaf_addr_t *lcaf);
patricia_tree_t *_get_local_db_for_addr(mdb_t *db, lisp_addr_t *addr);


#define mdb_foreach_entry(_mdb, _it) \
    do {                                                                            \
        void * _pt_;                                                                 \
        glist_entry_t *_pt_it_;                                                     \
        patricia_tree_t *_ptree_;                                                   \
        patricia_node_t *_node, *_nodein;                                           \
        glist_t *_pt_list_ = glist_new();                                           \
        glist_add((_mdb)->AF4_ip_db,_pt_list_);                                     \
        glist_add((_mdb)->AF6_ip_db,_pt_list_);                                     \
        int_htable_foreach_value((_mdb)->AF4_iid_db,_pt_){                          \
            glist_add(_pt_,_pt_list_);                                              \
        }int_htable_foreach_value_end;                                              \
        int_htable_foreach_value((_mdb)->AF6_iid_db,_pt_){                          \
            glist_add(_pt_,_pt_list_);                                              \
        }int_htable_foreach_value_end;                                              \
        glist_add((_mdb)->AF4_mc_db,_pt_list_);                                     \
        glist_add((_mdb)->AF4_mc_db,_pt_list_);                                     \
        glist_for_each_entry(_pt_it_, _pt_list_){                                   \
            _ptree_ = (patricia_tree_t *)glist_entry_data(_pt_it_);                 \
            PATRICIA_WALK(_ptree_->head, _node) {                                   \
                PATRICIA_WALK(((patricia_tree_t *)(_node->data))->head, _nodein) {  \
                    if ((_it = _nodein->data)){

#define mdb_foreach_entry_end           \
                    }                   \
                } PATRICIA_WALK_END;    \
            } PATRICIA_WALK_END;        \
        }                               \
        glist_destroy(_pt_list_);       \
    } while (0)


#define mdb_foreach_entry_with_break(_mdb, _it, _break) \
    do {                                                                            \
        void * _pt_;                                                                 \
        glist_entry_t *_pt_it_;                                                     \
        patricia_tree_t *_ptree_;                                                   \
        patricia_node_t *_node, *_nodein;                                           \
        glist_t *_pt_list_ = glist_new();                                           \
        glist_add((_mdb)->AF4_ip_db,_pt_list_);                                     \
        glist_add((_mdb)->AF6_ip_db,_pt_list_);                                     \
        int_htable_foreach_value((_mdb)->AF4_iid_db,_pt_){                          \
            glist_add(_pt_,_pt_list_);                                              \
        }int_htable_foreach_value_end;                                              \
        int_htable_foreach_value((_mdb)->AF6_iid_db,_pt_){                          \
            glist_add(_pt_,_pt_list_);                                              \
        }int_htable_foreach_value_end;                                              \
        glist_add((_mdb)->AF4_mc_db,_pt_list_);                                     \
        glist_add((_mdb)->AF4_mc_db,_pt_list_);                                     \
        glist_for_each_entry(_pt_it_, _pt_list_){                                   \
            _ptree_ = (patricia_tree_t *)glist_entry_data(_pt_it_);                 \
            PATRICIA_WALK(_ptree_->head, _node) {                                   \
                PATRICIA_WALK(((patricia_tree_t *)(_node->data))->head, _nodein) {  \
                    if ((_it = _nodein->data)){

#define mdb_foreach_entry_with_break_end(_break) \
                        if (_break){    \
                            break;      \
                        }               \
                    }                   \
                } PATRICIA_WALK_END;    \
                if (_break){            \
                    break;              \
                }                       \
            } PATRICIA_WALK_END;        \
            if (_break){                \
                break;                  \
            }                           \
        }                               \
        glist_destroy(_pt_list_);       \
    } while (0)


#define mdb_foreach_ip_entry(_mdb, _it)                                             \
    do {                                                                            \
        void * _pt_;                                                                \
        glist_entry_t *_pt_it_;                                                     \
        patricia_tree_t *_ptree_;                                                   \
        patricia_node_t *_node, *_nodein;                                           \
        glist_t *_pt_list_ = glist_new();                                           \
        glist_add((_mdb)->AF4_ip_db,_pt_list_);                                     \
        glist_add((_mdb)->AF6_ip_db,_pt_list_);                                     \
        int_htable_foreach_value((_mdb)->AF4_iid_db,_pt_){                          \
            glist_add(_pt_,_pt_list_);                                              \
        }int_htable_foreach_value_end;                                              \
        int_htable_foreach_value((_mdb)->AF6_iid_db,_pt_){                          \
            glist_add(_pt_,_pt_list_);                                              \
        }int_htable_foreach_value_end;                                              \
        glist_for_each_entry(_pt_it_, _pt_list_){                                   \
            _ptree_ = (patricia_tree_t *)glist_entry_data(_pt_it_);                 \
            PATRICIA_WALK(_ptree_->head, _node) {                                   \
                PATRICIA_WALK(((patricia_tree_t *)(_node->data))->head, _nodein) {  \
                if ((_it = _nodein->data)){

#define mdb_foreach_ip_entry_end        \
                }                       \
                } PATRICIA_WALK_END;    \
            } PATRICIA_WALK_END;        \
        }                               \
        glist_destroy(_pt_list_);       \
    } while (0)


#define mdb_foreach_ip_entry_with_break(_mdb, _it, _break)                          \
    do {                                                                            \
        void * _pt_;                                                                \
        glist_entry_t *_pt_it_;                                                     \
        patricia_tree_t *_ptree_;                                                   \
        patricia_node_t *_node, *_nodein;                                           \
        glist_t *_pt_list_ = glist_new();                                           \
        glist_add((_mdb)->AF4_ip_db,_pt_list_);                                     \
        glist_add((_mdb)->AF6_ip_db,_pt_list_);                                     \
        int_htable_foreach_value((_mdb)->AF4_iid_db,_pt_){                          \
            glist_add(_pt_,_pt_list_);                                              \
        }int_htable_foreach_value_end;                                              \
        int_htable_foreach_value((_mdb)->AF6_iid_db,_pt_){                          \
            glist_add(_pt_,_pt_list_);                                              \
        }int_htable_foreach_value_end;                                              \
        glist_for_each_entry(_pt_it_, _pt_list_){                                   \
            _ptree_ = (patricia_tree_t *)glist_entry_data(_pt_it_);                 \
            PATRICIA_WALK(_ptree_->head, _node) {                                   \
                PATRICIA_WALK(((patricia_tree_t *)(_node->data))->head, _nodein) {  \
                    if ((_it = _nodein->data)){

#define mdb_foreach_ip_entry_with_break_end(_break)        \
                        if (_break){    \
                            break;      \
                        }               \
                    }                   \
                } PATRICIA_WALK_END;    \
                if (_break){            \
                    break;              \
                }                       \
            } PATRICIA_WALK_END;        \
            if (_break){                \
                break;                  \
            }                           \
        } glist_destroy(_pt_list_);     \
    } while (0)

#define mdb_foreach_mc_entry(_mdb, _it) \
    do { \
        patricia_tree_t *_ptstack[2] = {(_mdb)->AF4_mc_db, (_mdb)->AF6_mc_db};  \
        patricia_node_t *_node, *_nodemc;                                       \
        int _i;                                                                 \
        for (_i=0; _i < 2; _i++) {                                              \
            PATRICIA_WALK(_ptstack[_i]->head, _node) {                          \
                PATRICIA_WALK(((patricia_tree_t *)(_node->data))->head, _nodemc) {      \
                    if ((_it = _nodemc->data)){

#define mdb_foreach_mc_entry_end \
                    }                   \
                } PATRICIA_WALK_END;    \
            } PATRICIA_WALK_END;        \
        }                               \
    } while (0)


#define mdb_foreach_entry_in_ip_eid_db(_mdb, _eid, _it) \
    do { \
        patricia_tree_t * _eid_db; \
        patricia_node_t *_node;  \
        _eid_db = _get_local_db_for_addr(_mdb, (_eid)); \
        if (_eid_db){ \
            PATRICIA_WALK(_eid_db->head, _node){ \
                if (((_it) = _node->data)){
#define mdb_foreach_entry_in_ip_eid_db_end \
                }               \
            }PATRICIA_WALK_END; \
        } \
    } while(0)




#endif /* MAPPING_DB_H_ */

