/*
 *
 */

typedef struct ftpl_map_db{
    uint32_t                        iid;
    lisp_addr_t                     src_addr;
    lisp_addr_t                     dst_addr;
    uint16_t                        src_port;
    uint16_t                        dst_port;
    uint8_t                         protocol;
} ftpl_map_db_t;


ftpl_map_db_t *
ftpl_map_db_new () {
    ftpl_map_db_t *db;
    db = xzalloc(sizeof(ftpl_map_db_t));
}

ftpl_map_db_entry(){

}
