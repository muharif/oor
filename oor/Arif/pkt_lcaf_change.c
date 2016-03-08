/*
 *
 */

/* Calculate the hash of the 5 tuples of a packet */
uint32_t
lcaf_tuple_hash(lisp_addr_t *lsp)
{
    packet_tuple_t *tuple;
    int hash = 0;
    int len = 0;

    tuple = lisp_addr_get_lcaf(lsp);
    int port = tuple->src_port;
    uint32_t *tuples = NULL;

    port = port + ((int)tuple->dst_port << 16);
    switch (lisp_addr_ip_afi(&tuple->src_addr)){
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
    t1=lisp_addr_get_lcaf(lsp1);
    t2=lisp_addr_get_lcaf(lsp2);
	return(t1->src_port == t2->src_port
           && t1->dst_port == t2->dst_port
           && (lisp_addr_cmp(&t1->src_addr, &t2->src_addr) == 0)
           && (lisp_addr_cmp(&t1->dst_addr, &t2->dst_addr) == 0)
           && t1->iid == t2->iid);
}
