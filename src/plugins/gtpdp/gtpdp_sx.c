/*
 * Copyright (c) 2017 Travelping GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _LGPL_SOURCE            /* LGPL v3.0 is compatible with Apache 2.0 */
#include <urcu-qsbr.h>          /* QSBR RCU flavor */

#include <rte_config.h>
#include <rte_common.h>
#include <rte_acl.h>

#include <stdio.h>
#include <setjmp.h>
#include <signal.h>
#include <inttypes.h>
#include <vppinfra/clib.h>
#include <vppinfra/mem.h>
#include <vppinfra/pool.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/format.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <search.h>
#include <netinet/ip.h>

#include "pfcp.h"
#include "gtpdp.h"
#include "gtpdp_sx.h"
#include "gtpdp_sx_api.h"

gtpdp_main_t gtpdp_main;

#define SESS_CREATE 0
#define SESS_MODIFY 1
#define SESS_DEL 2

#define OFF_ETHHEAD     (sizeof(struct ether_hdr))
#define OFF_IPV42PROTO (offsetof(struct ipv4_hdr, next_proto_id))
#define OFF_IPV62PROTO (offsetof(struct ipv6_hdr, proto))
#define MBUF_IPV4_2PROTO(m)     \
	rte_pktmbuf_mtod_offset((m), uint8_t *, OFF_ETHHEAD + OFF_IPV42PROTO)
#define MBUF_IPV6_2PROTO(m)     \
	rte_pktmbuf_mtod_offset((m), uint8_t *, OFF_ETHHEAD + OFF_IPV62PROTO)

static void sx_add_del_vrf_ip(const void *vrf_ip, void *si, int is_add);
static void sx_add_del_v4_teid(const void *teid, void *si, int is_add);
static void sx_add_del_v6_teid(const void *teid, void *si, int is_add);
static void sx_acl_free(gtpdp_acl_ctx_t *ctx);

/* DPDK ACL defines */

enum {
  PROTO_FIELD_IPV4,
  SRC_FIELD_IPV4,
  DST_FIELD_IPV4,
  SRCP_FIELD_IPV4,
  DSTP_FIELD_IPV4,
  GTP_TEID_IPV4
};

enum {
  RTE_ACL_IPV4VLAN_PROTO,
  RTE_ACL_IPV4VLAN_VLAN,
  RTE_ACL_IPV4VLAN_SRC,
  RTE_ACL_IPV4VLAN_DST,
  RTE_ACL_IPV4VLAN_PORTS,
  RTE_ACL_IPV4_GTP_TEID
};

struct rte_acl_field_def ipv4_defs[] = {
  [PROTO_FIELD_IPV4] =
  {
    .type = RTE_ACL_FIELD_TYPE_BITMASK,
    .size = sizeof(uint8_t),
    .field_index = PROTO_FIELD_IPV4,
    .input_index = RTE_ACL_IPV4VLAN_PROTO,
    .offset = offsetof(ip4_header_t, protocol),
  },
  [SRC_FIELD_IPV4] =
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = sizeof(uint32_t),
    .field_index = SRC_FIELD_IPV4,
    .input_index = RTE_ACL_IPV4VLAN_SRC,
    .offset = offsetof(ip4_header_t, src_address),
  },
  [DST_FIELD_IPV4] =
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = sizeof(uint32_t),
    .field_index = DST_FIELD_IPV4,
    .input_index = RTE_ACL_IPV4VLAN_DST,
    .offset = offsetof(ip4_header_t, dst_address),
  },
  [SRCP_FIELD_IPV4] =
  {
    .type = RTE_ACL_FIELD_TYPE_RANGE,
    .size = sizeof(uint16_t),
    .field_index = SRCP_FIELD_IPV4,
    .input_index = RTE_ACL_IPV4VLAN_PORTS,
    .offset = sizeof(ip4_header_t),
  },
  [DSTP_FIELD_IPV4] =
  {
    .type = RTE_ACL_FIELD_TYPE_RANGE,
    .size = sizeof(uint16_t),
    .field_index = DSTP_FIELD_IPV4,
    .input_index = RTE_ACL_IPV4VLAN_PORTS,
    .offset = sizeof(ip4_header_t) + sizeof(uint16_t),
  },
  [GTP_TEID_IPV4] =
  {
    .type = RTE_ACL_FIELD_TYPE_BITMASK,
    .size = sizeof(u32),
    .field_index = GTP_TEID_IPV4,
    .input_index = RTE_ACL_IPV4_GTP_TEID,
    .offset = sizeof(ip4_header_t) + sizeof(udp_header_t),
  }
};

RTE_ACL_RULE_DEF(acl4_rule, RTE_DIM(ipv4_defs));

enum {
  PROTO_FIELD_IPV6,
  SRC1_FIELD_IPV6,
  SRC2_FIELD_IPV6,
  SRC3_FIELD_IPV6,
  SRC4_FIELD_IPV6,
  DST1_FIELD_IPV6,
  DST2_FIELD_IPV6,
  DST3_FIELD_IPV6,
  DST4_FIELD_IPV6,
  SRCP_FIELD_IPV6,
  DSTP_FIELD_IPV6,
  GTP_TEID_IPV6
};

struct rte_acl_field_def ipv6_defs[] = {
  [PROTO_FIELD_IPV6] =
  {
    .type = RTE_ACL_FIELD_TYPE_BITMASK,
    .size = sizeof(uint8_t),
    .field_index = PROTO_FIELD_IPV6,
    .input_index = PROTO_FIELD_IPV6,
    .offset = offsetof(ip6_header_t, protocol),
  },
  [SRC1_FIELD_IPV6] =
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = sizeof(uint32_t),
    .field_index = SRC1_FIELD_IPV6,
    .input_index = SRC1_FIELD_IPV6,
    .offset = offsetof(ip6_header_t, src_address.as_u32[0]),
  },
  [SRC2_FIELD_IPV6] =
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = sizeof(uint32_t),
    .field_index = SRC2_FIELD_IPV6,
    .input_index = SRC2_FIELD_IPV6,
    .offset = offsetof(ip6_header_t, src_address.as_u32[1]),
  },
  [SRC3_FIELD_IPV6] =
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = sizeof(uint32_t),
    .field_index = SRC3_FIELD_IPV6,
    .input_index = SRC3_FIELD_IPV6,
    .offset = offsetof(ip6_header_t, src_address.as_u32[2]),
  },
  [SRC4_FIELD_IPV6] =
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = sizeof(uint32_t),
    .field_index = SRC4_FIELD_IPV6,
    .input_index = SRC4_FIELD_IPV6,
    .offset = offsetof(ip6_header_t, src_address.as_u32[3]),
  },
  [DST1_FIELD_IPV6] =
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = sizeof(uint32_t),
    .field_index = DST1_FIELD_IPV6,
    .input_index = DST1_FIELD_IPV6,
    .offset = offsetof(ip6_header_t, dst_address.as_u32[0]),
  },
  [DST2_FIELD_IPV6] =
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = sizeof(uint32_t),
    .field_index = DST2_FIELD_IPV6,
    .input_index = DST2_FIELD_IPV6,
    .offset = offsetof(ip6_header_t, dst_address.as_u32[1]),
  },
  [DST3_FIELD_IPV6] =
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = sizeof(uint32_t),
    .field_index = DST3_FIELD_IPV6,
    .input_index = DST3_FIELD_IPV6,
    .offset = offsetof(ip6_header_t, dst_address.as_u32[2]),
  },
  [DST4_FIELD_IPV6] =
  {
    .type = RTE_ACL_FIELD_TYPE_MASK,
    .size = sizeof(uint32_t),
    .field_index = DST4_FIELD_IPV6,
    .input_index = DST4_FIELD_IPV6,
    .offset = offsetof(ip6_header_t, dst_address.as_u32[3]),
  },
  [SRCP_FIELD_IPV6] =
  {
    .type = RTE_ACL_FIELD_TYPE_RANGE,
    .size = sizeof(uint16_t),
    .field_index = SRCP_FIELD_IPV6,
    .input_index = SRCP_FIELD_IPV6,
    .offset = sizeof(ip6_header_t),
  },
  [DSTP_FIELD_IPV6] =
  {
    .type = RTE_ACL_FIELD_TYPE_RANGE,
    .size = sizeof(uint16_t),
    .field_index = DSTP_FIELD_IPV6,
    .input_index = SRCP_FIELD_IPV6,
    .offset = sizeof(ip6_header_t) + sizeof(uint16_t),
  },
  [GTP_TEID_IPV6] =
  {
    .type = RTE_ACL_FIELD_TYPE_BITMASK,
    .size = sizeof(u32),
    .field_index = GTP_TEID_IPV6,
    .input_index = GTP_TEID_IPV6,
    .offset = sizeof(ip6_header_t) + sizeof(udp_header_t),
  }
};

RTE_ACL_RULE_DEF(acl6_rule, RTE_DIM(ipv6_defs));

#define vec_bsearch(k, v, compar)				\
	bsearch((k), (v), vec_len((v)), sizeof((v)[0]), compar)

static u8 *
format_gtpdp_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "gtpdp_session%d", dev_instance);
}

static clib_error_t *
gtpdp_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  u32 hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
    VNET_HW_INTERFACE_FLAG_LINK_UP : 0;
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

  return /* no error */ 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (gtpu_device_class,static) = {
  .name = "GTPU",
  .format_device_name = format_gtpdp_name,
  .format_tx_trace = format_gtpdp_encap_trace,
  .admin_up_down_function = gtpdp_interface_admin_up_down,
};
/* *INDENT-ON* */

static u8 *
format_gtpu_header_with_length (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  s = format (s, "unimplemented dev %u", dev_instance);
  return s;
}

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (gtpu_hw_class) =
{
  .name = "GTPU",
  .format_header = format_gtpu_header_with_length,
  .build_rewrite = default_build_rewrite,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};
/* *INDENT-ON* */

/**
 * Compare integer ids.
 */
#define intcmp(a, b)                                    \
	({                                              \
		typeof (a) a_ = (a);                    \
		typeof (b) b_ = (b);                    \
		(a_) < (b_) ? -1 : (a_) > (b_) ? 1 : 0; \
	})

static int sx_pdr_id_compare(const void *p1, const void *p2)
{
	const gtpdp_pdr_t *a = (gtpdp_pdr_t *)p1;
	const gtpdp_pdr_t *b = (gtpdp_pdr_t *)p2;

	/* compare rule_ids */
	return intcmp(a->id, b->id);
}

#define vec_diff(new, old, compar, add_del, user)			\
  do {									\
    size_t _i = 0, _j = 0;						\
									\
    if (new)								\
      vec_sort_with_function(new,compar);				\
    if (old)								\
      vec_sort_with_function(old,compar);				\
    if (new && old)							\
      while (_i < vec_len(new) && _j < vec_len(old)) {			\
	int r = compar(&vec_elt(new, _i), &vec_elt(old, _j));		\
	if (r == 0) {							\
	  _i++;;							\
	  _j++;								\
	} else if (r < 0) {						\
	  /* insert new entry */					\
	  add_del(&vec_elt(new, _i), user, 1);				\
	  _i++;								\
	} else {							\
	  /* remove old entry */					\
	  add_del(&vec_elt(old, _j), user, 0);				\
	  _j++;								\
	}								\
      }									\
									\
    if (new)								\
      for (;_i < vec_len(new); _i++)					\
	/* insert new entry */						\
	add_del(&vec_elt(new, _i), user, 1);				\
    if (old)								\
      for (;_j < vec_len(old); _j++)					\
	/* remove old entry */						\
	add_del(&vec_elt(old, _j), user, 0);				\
  } while (0)

static int sx_far_id_compare(const void *p1, const void *p2)
{
	const gtpdp_far_t *a = (gtpdp_far_t *)p1;
	const gtpdp_far_t *b = (gtpdp_far_t *)p2;

	/* compare rule_ids */
	return intcmp(a->id, b->id);
}

static int sx_urr_id_compare(const void *p1, const void *p2)
{
	const gtpdp_urr_t *a = (gtpdp_urr_t *)p1;
	const gtpdp_urr_t *b = (gtpdp_urr_t *)p2;

	/* compare rule_ids */
	return intcmp(a->id, b->id);
}

gtpdp_node_assoc_t *sx_get_association(pfcp_node_id_t *node_id)
{
  gtpdp_main_t *gtm = &gtpdp_main;
  uword *p = NULL;

  switch (node_id->type)
    {
    case NID_IPv4:
    case NID_IPv6:
      p = hash_get_mem (gtm->node_index_by_ip, &node_id->ip);
      break;

    case NID_FQDN:
      p = hash_get_mem (gtm->node_index_by_fqdn, node_id->fqdn);
      break;
    }

  if (!p)
    return 0;

  return pool_elt_at_index (gtm->nodes, p[0]);
}

gtpdp_node_assoc_t *sx_new_association(pfcp_node_id_t *node_id)
{
  gtpdp_main_t *gtm = &gtpdp_main;
  gtpdp_node_assoc_t *n;

  pool_get_aligned (gtm->nodes, n, CLIB_CACHE_LINE_BYTES);
  memset (n, 0, sizeof (*n));
  n->node_id = *node_id;

  switch (node_id->type)
    {
    case NID_IPv4:
    case NID_IPv6:
      hash_set_mem_alloc (&gtm->node_index_by_ip, &node_id->ip, n - gtm->nodes);
      break;

    case NID_FQDN:
      hash_set_mem (gtm->node_index_by_fqdn, node_id->fqdn, n - gtm->nodes);
      break;
    }

  return n;
}

void sx_release_association(gtpdp_node_assoc_t *n)
{
  gtpdp_main_t *gtm = &gtpdp_main;

  switch (n->node_id.type)
    {
    case NID_IPv4:
    case NID_IPv6:
      hash_unset_mem_free (&gtm->node_index_by_ip, &n->node_id.ip);
      break;

    case NID_FQDN:
      hash_unset_mem (gtm->node_index_by_fqdn, n->node_id.fqdn);
      vec_free(n->node_id.fqdn);
      break;
    }

  pool_put(gtm->nodes, n);
}

gtpdp_session_t *sx_create_session(uint64_t cp_f_seid, u64 session_handle)
{
  vnet_main_t *vnm = gtpdp_main.vnet_main;
  l2input_main_t *l2im = &l2input_main;
  gtpdp_main_t *gtm = &gtpdp_main;
  u32 hw_if_index = ~0;
  u32 sw_if_index = ~0;
  gtpdp_session_t *sx;

  pool_get_aligned (gtm->sessions, sx, CLIB_CACHE_LINE_BYTES);
  memset (sx, 0, sizeof (*sx));

  sx->cp_f_seid = cp_f_seid;
  sx->session_handle = session_handle;
  //TODO sx->up_f_seid = sx - gtm->sessions;
  hash_set (gtm->session_by_id, cp_f_seid, sx - gtm->sessions);

  vnet_hw_interface_t *hi;

  if (vec_len (gtm->free_session_hw_if_indices) > 0)
  {
    vnet_interface_main_t *im = &vnm->interface_main;
    hw_if_index = gtm->free_session_hw_if_indices
      [vec_len (gtm->free_session_hw_if_indices) - 1];
    _vec_len (gtm->free_session_hw_if_indices) -= 1;

    hi = vnet_get_hw_interface (vnm, hw_if_index);
    hi->dev_instance = sx - gtm->sessions;
    hi->hw_instance = hi->dev_instance;

    /* clear old stats of freed session before reuse */
    sw_if_index = hi->sw_if_index;
    vnet_interface_counter_lock (im);
    vlib_zero_combined_counter
      (&im->combined_sw_if_counters[VNET_INTERFACE_COUNTER_TX], sw_if_index);
    vlib_zero_combined_counter
      (&im->combined_sw_if_counters[VNET_INTERFACE_COUNTER_RX], sw_if_index);
    vlib_zero_simple_counter
      (&im->sw_if_counters[VNET_INTERFACE_COUNTER_DROP], sw_if_index);
    vnet_interface_counter_unlock (im);
  }
  else
    {
      hw_if_index = vnet_register_interface
	(vnm, gtpu_device_class.index, sx - gtm->sessions,
	 gtpu_hw_class.index, sx - gtm->sessions);
      hi = vnet_get_hw_interface (vnm, hw_if_index);
    }

  /* Set GTP-U tunnel output node */
  vnet_set_interface_output_node (vnm, hw_if_index, gtpdp_if_input_node.index);

  sx->hw_if_index = hw_if_index;
  sx->sw_if_index = sw_if_index = hi->sw_if_index;

  vec_validate_init_empty (gtm->session_index_by_sw_if_index, sw_if_index, ~0);
  gtm->session_index_by_sw_if_index[sw_if_index] = sx - gtm->sessions;

  /* setup l2 input config with l2 feature and bd 0 to drop packet */
  vec_validate (l2im->configs, sw_if_index);
  l2im->configs[sw_if_index].feature_bitmap = L2INPUT_FEAT_DROP;
  l2im->configs[sw_if_index].bd_index = 0;

  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
  si->flags &= ~VNET_SW_INTERFACE_FLAG_HIDDEN;
  vnet_sw_interface_set_flags (vnm, sw_if_index, VNET_SW_INTERFACE_FLAG_ADMIN_UP);

  /*
   * L3 enable the interface
   */
  ip4_sw_interface_enable_disable (sw_if_index, 1);
  ip6_sw_interface_enable_disable (sw_if_index, 1);

  // TODO: setup FIBs

  vnet_get_sw_interface (vnet_get_main (), sw_if_index)->flood_class =
	  VNET_FLOOD_CLASS_TUNNEL_NORMAL;

  return sx;
}

void sx_update_session(gtpdp_session_t *sx)
{
	// TODO: do we need some kind of update lock ?
}

static void
gtpdp_peer_restack_dpo (gtpdp_peer_t * p)
{
  dpo_id_t dpo = DPO_INVALID;

  fib_entry_contribute_forwarding (p->fib_entry_index, p->forw_type, &dpo);
  dpo_stack_from_node (p->encap_index, &p->next_dpo, &dpo);
  dpo_reset (&dpo);
}

static gtpdp_peer_t *
gtpdp_peer_from_fib_node (fib_node_t * node)
{
  return ((gtpdp_peer_t *) (((char *) node) -
			    STRUCT_OFFSET_OF (gtpdp_peer_t, node)));
}

/**
 * Function definition to backwalk a FIB node -
 * Here we will restack the new dpo of GTPU DIP to encap node.
 */
static fib_node_back_walk_rc_t
gtpdp_peer_back_walk (fib_node_t * node, fib_node_back_walk_ctx_t * ctx)
{
  gtpdp_peer_restack_dpo (gtpdp_peer_from_fib_node (node));
  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/**
 * Function definition to get a FIB node from its index
 */
static fib_node_t *
gtpdp_peer_fib_node_get (fib_node_index_t index)
{
  gtpdp_main_t *gtm = &gtpdp_main;
  gtpdp_peer_t *p;

  p = pool_elt_at_index (gtm->peers, index);

  return (&p->node);
}

/**
 * Function definition to inform the FIB node that its last lock has gone.
 */
static void
gtpdp_peer_last_lock_gone (fib_node_t * node)
{
  /*
   * The GTP peer is a root of the graph. As such
   * it never has children and thus is never locked.
   */
  ASSERT (0);
}

/*
 * Virtual function table registered by GTPU tunnels
 * for participation in the FIB object graph.
 */
const fib_node_vft_t gtpdp_vft = {
  .fnv_get = gtpdp_peer_fib_node_get,
  .fnv_last_lock = gtpdp_peer_last_lock_gone,
  .fnv_back_walk = gtpdp_peer_back_walk,
};

static u32 nwi_to_vrf(uword nwi)
{
  gtpdp_main_t *gtm = &gtpdp_main;
  gtpdp_nwi_t * n;

  if (!pool_is_free_index (gtm->nwis, nwi))
    {
      n = pool_elt_at_index (gtm->nwis, nwi);
      return n->vrf;
    }

  return 0;
}

static uword
peer_addr_ref (ip46_address_t * ip, uword nwi)
{
  gtpdp_main_t *gtm = &gtpdp_main;
  ip46_address_fib_t key;
  u32 encap_fib_index;
  gtpdp_peer_t * p;
  uword *peer;
  int is_ip4;
  u32 vrf;

  is_ip4 = ip46_address_is_ip4 (ip);
  vrf = nwi_to_vrf(nwi);
  encap_fib_index = fib_table_find (is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6, vrf);

  key.addr = *ip;
  key.fib_index = encap_fib_index;

  peer = hash_get_mem (gtm->peer_index_by_ip, &key);
  if (peer)
    {
      p = pool_elt_at_index (gtm->peers, peer[0]);
      return peer[0];
    }

  pool_get_aligned (gtm->peers, p, CLIB_CACHE_LINE_BYTES);
  memset (p, 0, sizeof (*p));
  p->ref_cnt = 1;
  p->encap_fib_index = encap_fib_index;

  if (is_ip4)
    {
      p->encap_index = gtpdp4_encap_node.index;
      p->forw_type = FIB_FORW_CHAIN_TYPE_UNICAST_IP4;
    }
  else
    {
      p->encap_index = gtpdp6_encap_node.index;
      p->forw_type = FIB_FORW_CHAIN_TYPE_UNICAST_IP6;
    }

  hash_set_mem_alloc (&gtm->peer_index_by_ip, &key, p - gtm->peers);

  fib_node_init (&p->node, gtm->fib_node_type);
  fib_prefix_t tun_dst_pfx;
  fib_prefix_from_ip46_addr (ip, &tun_dst_pfx);

  p->fib_entry_index = fib_table_entry_special_add
    (p->encap_fib_index, &tun_dst_pfx, FIB_SOURCE_RR,
     FIB_ENTRY_FLAG_NONE);
  p->sibling_index = fib_entry_child_add
    (p->fib_entry_index, gtm->fib_node_type, p - gtm->peers);
  gtpdp_peer_restack_dpo (p);

  return p - gtm->peers;
}

static uword
peer_addr_unref (ip46_address_t * ip, uword nwi)
{
  gtpdp_main_t *gtm = &gtpdp_main;
  ip46_address_fib_t key;
  u32 encap_fib_index;
  gtpdp_peer_t * p;
  uword *peer;
  int is_ip4;
  u32 vrf;

  is_ip4 = ip46_address_is_ip4 (ip);
  vrf = nwi_to_vrf(nwi);
  encap_fib_index = fib_table_find (is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6, vrf);

  key.addr = *ip;
  key.fib_index = encap_fib_index;

  peer = hash_get_mem (gtm->peer_index_by_ip, &key);
  ASSERT (peer);

  p = pool_elt_at_index (gtm->peers, peer[0]);
  if (--(p->ref_cnt) != 0)
    return p->ref_cnt;

  hash_unset_mem_free (&gtm->peer_index_by_ip, &key);

  fib_entry_child_remove (p->fib_entry_index, p->sibling_index);
  fib_table_entry_delete_index (p->fib_entry_index, FIB_SOURCE_RR);
  fib_node_deinit (&p->node);
  pool_put (gtm->peers, p);

  return 0;
}

static int make_pending_pdr(gtpdp_session_t *sx)
{
  struct rules *pending = sx_get_rules(sx, SX_PENDING);
  struct rules *active = sx_get_rules(sx, SX_ACTIVE);

  if (pending->pdr)
    return 0;

  if (active->pdr) {
    size_t i;

    pending->pdr = vec_dup(active->pdr);
    vec_foreach_index (i, active->pdr) {
      vec_elt(pending->pdr, i).urr_ids =
	vec_dup(vec_elt(active->pdr, i).urr_ids);
    }
  }
  return 0;
}

static int make_pending_far(gtpdp_session_t *sx)
{
  struct rules *pending = sx_get_rules(sx, SX_PENDING);
  struct rules *active = sx_get_rules(sx, SX_ACTIVE);

  if (pending->far)
    return 0;

  if (active->far)
    pending->far = vec_dup(active->far);

  return 0;
}

static int make_pending_urr(gtpdp_session_t *sx)
{
  struct rules *pending = sx_get_rules(sx, SX_PENDING);
  struct rules *active = sx_get_rules(sx, SX_ACTIVE);
  gtpdp_urr_t *urr;

  if (pending->urr)
    return 0;

  if (active->urr)
    {
      pending->urr = vec_dup(active->urr);
      vec_foreach (urr, pending->urr)
	{
	  memset(&urr->measurement.volume, 0, sizeof(urr->measurement.volume));
	  vlib_validate_combined_counter(&urr->measurement.volume, URR_COUNTER_NUM);
	}
    }

  return 0;
}

static void sx_free_rules(gtpdp_session_t *sx, int rule)
{
  struct rules *rules = sx_get_rules(sx, rule);
  gtpdp_pdr_t *pdr;
  gtpdp_far_t *far;
  gtpdp_urr_t *urr;

  vec_foreach (pdr, rules->pdr)
    vec_free(pdr->urr_ids);
  vec_free(rules->pdr);
  vec_foreach (far, rules->far)
    {
      if (far->forward.outer_header_creation != 0)
	peer_addr_unref(&far->forward.addr, far->forward.nwi);
      vec_free(far->forward.rewrite);
    }
  vec_free(rules->far);
  vec_foreach (urr, rules->urr)
    vlib_free_combined_counter(&urr->measurement.volume);
  vec_free(rules->urr);
  for (size_t i = 0; i < ARRAY_LEN(rules->sdf); i++)
    sx_acl_free(&rules->sdf[i]);
  vec_free(rules->vrf_ip);
  vec_free(rules->v4_teid);
  vec_free(rules->v6_teid);

  hash_free(rules->v4_wildcard_teid);
  hash_free(rules->v6_wildcard_teid);

  memset(rules, 0, sizeof(*rules));
}

static void rcu_free_sx_session_info(struct rcu_head *head)
{
  gtpdp_session_t *sx = caa_container_of(head, gtpdp_session_t, rcu_head);
  gtpdp_main_t *gtm = &gtpdp_main;

  for (size_t i = 0; i < ARRAY_LEN(sx->rules); i++)
    sx_free_rules(sx, i);

  vec_add1 (gtm->free_session_hw_if_indices, sx->hw_if_index);
  pool_put (gtm->sessions, sx);
}

int sx_disable_session(gtpdp_session_t *sx)
{
  struct rules *active = sx_get_rules(sx, SX_ACTIVE);
  vnet_main_t *vnm = gtpdp_main.vnet_main;
  gtpdp_main_t *gtm = &gtpdp_main;
  ip46_address_fib_t *vrf_ip;
  gtpu4_tunnel_key_t *v4_teid;
  gtpu6_tunnel_key_t *v6_teid;

  hash_unset (gtm->session_by_id, sx->cp_f_seid);
  vec_foreach (v4_teid, active->v4_teid)
    sx_add_del_v4_teid(v4_teid, sx, 0);
  vec_foreach (v6_teid, active->v6_teid)
    sx_add_del_v6_teid(v6_teid, sx, 0);
  vec_foreach (vrf_ip, active->vrf_ip)
    sx_add_del_vrf_ip(vrf_ip, sx, 0);

  //TODO: free DL fifo...

  /* disable tunnel if */
  vnet_sw_interface_set_flags (vnm, sx->sw_if_index, 0 /* down */ );
  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sx->sw_if_index);
  si->flags |= VNET_SW_INTERFACE_FLAG_HIDDEN;

  /* make sure session is removed from l2 bd or xconnect */
  set_int_l2_mode (gtm->vlib_main, vnm, MODE_L3, sx->sw_if_index, 0, 0, 0, 0);
  gtm->session_index_by_sw_if_index[sx->sw_if_index] = ~0;

  return 0;
}

void sx_free_session(gtpdp_session_t *sx)
{
	call_rcu(&sx->rcu_head, rcu_free_sx_session_info);
}

#define sx_rule_vector_fns(t)						\
gtpdp_##t##_t * sx_get_##t##_by_id(struct rules *rules,			\
				   typeof (((gtpdp_##t##_t *)0)->id) t##_id) \
{									\
  gtpdp_##t##_t r = { .id = t##_id };					\
									\
  return vec_bsearch(&r, rules->t, sx_##t##_id_compare);		\
}									\
									\
gtpdp_##t##_t *sx_get_##t(gtpdp_session_t *sx, int rule,		\
			  typeof (((gtpdp_##t##_t *)0)->id) t##_id)	\
{									\
  struct rules *rules = sx_get_rules(sx, rule);				\
  gtpdp_##t##_t r = { .id = t##_id };					\
									\
  if (rule == SX_PENDING)						\
    if (make_pending_##t(sx) != 0)					\
      return NULL;							\
									\
  printf("LOOKUP t##: %u\n", t##_id);					\
  return vec_bsearch(&r, rules->t, sx_##t##_id_compare);		\
}									\
									\
int sx_create_##t(gtpdp_session_t *sx, gtpdp_##t##_t *t)		\
{									\
  struct rules *rules = sx_get_rules(sx, SX_PENDING);			\
									\
  if (make_pending_##t(sx) != 0)					\
    return -1;								\
									\
  vec_add1(rules->t, *t);						\
  vec_sort_with_function(rules->t, sx_##t##_id_compare);		\
  return 0;								\
}									\
									\
int sx_delete_##t(gtpdp_session_t *sx, u32 t##_id)			\
{									\
  struct rules *rules = sx_get_rules(sx, SX_PENDING);			\
  gtpdp_##t##_t r = { .id = t##_id };					\
  gtpdp_##t##_t *p;							\
									\
  if (make_pending_##t(sx) != 0)					\
    return -1;								\
									\
  if (!(p = vec_bsearch(&r, rules->t, sx_##t##_id_compare)))		\
    return -1;								\
									\
  vec_del1(rules->t, p - rules->t);					\
  return 0;								\
}

sx_rule_vector_fns(pdr)
sx_rule_vector_fns(far)
sx_rule_vector_fns(urr)

void sx_send_end_marker(gtpdp_session_t *sx, u16 id)
{
  struct rules *rules = sx_get_rules(sx, SX_PENDING);

  vec_add1(rules->send_end_marker, id);
}

static int ip46_address_fib_cmp(const void *a0, const void *b0)
{
  const ip46_address_fib_t *a = a0;
  const ip46_address_fib_t *b = b0;
  int r;

  if ((r = intcmp(a->fib_index, b->fib_index)) != 0)
    return r;

  return ip46_address_cmp(&a->addr, &b->addr);
}

static int v4_teid_cmp(const void *a, const void *b)
{
  return memcmp(a, b, sizeof(gtpu4_tunnel_key_t));
}

static int v6_teid_cmp(const void *a, const void *b)
{
  return memcmp(a, b, sizeof(gtpu6_tunnel_key_t));
}

static void sx_add_del_vrf_ip(const void *ip, void *si, int is_add)
{
  const ip46_address_fib_t *vrf_ip = ip;
  gtpdp_session_t *sess = si;
  fib_prefix_t pfx;

  memset (&pfx, 0, sizeof (pfx));

  if (ip46_address_is_ip4(&vrf_ip->addr))
    {
      pfx.fp_addr.ip4.as_u32 = vrf_ip->addr.ip4.as_u32;
      pfx.fp_len = 32;
      pfx.fp_proto = FIB_PROTOCOL_IP4;
    }
  else
    {
      pfx.fp_addr.ip6.as_u64[0] = vrf_ip->addr.ip6.as_u64[0];
      pfx.fp_addr.ip6.as_u64[1] = vrf_ip->addr.ip6.as_u64[1];
      pfx.fp_len = 128;
      pfx.fp_proto = FIB_PROTOCOL_IP6;
    }

  if (is_add)
    {
      /* add reverse route for client ip */
      fib_table_entry_path_add (vrf_ip->fib_index, &pfx,
				FIB_SOURCE_PLUGIN_HI, FIB_ENTRY_FLAG_NONE,
				fib_proto_to_dpo (pfx.fp_proto),
				&pfx.fp_addr, sess->sw_if_index, ~0,
				1, NULL, FIB_ROUTE_PATH_FLAG_NONE);
    }
  else
    {
      /* delete reverse route for client ip */
      fib_table_entry_path_remove (vrf_ip->fib_index, &pfx,
				   FIB_SOURCE_PLUGIN_HI,
				   fib_proto_to_dpo (pfx.fp_proto),
				   &pfx.fp_addr,
				   sess->sw_if_index, ~0, 1,
				   FIB_ROUTE_PATH_FLAG_NONE);
    }
}

static void sx_add_del_v4_teid(const void *teid, void *si, int is_add)
{
  gtpdp_main_t *gtm = &gtpdp_main;
  gtpdp_session_t *sess = si;
  const gtpu4_tunnel_key_t *v4_teid = teid;
  clib_bihash_kv_8_8_t kv;

  kv.key = v4_teid->as_u64;
  kv.value = sess - gtm->sessions;

  clib_warning("gtpdp_sx: is_add: %d, TEID: 0x%08x, IP:%U, Session:%p, idx: %p.",
	       is_add, v4_teid->teid,
	       format_ip4_address, &v4_teid->dst, sess,
	       sess - gtm->sessions);

  clib_bihash_add_del_8_8(&gtm->v4_tunnel_by_key, &kv, is_add);
}

static void sx_add_del_v6_teid(const void *teid, void *si, int is_add)
{
  gtpdp_main_t *gtm = &gtpdp_main;
  gtpdp_session_t *sess = si;
  const gtpu6_tunnel_key_t *v6_teid = teid;
  clib_bihash_kv_24_8_t kv;

  kv.key[0] = v6_teid->dst.as_u64[0];
  kv.key[1] = v6_teid->dst.as_u64[1];
  kv.key[2] = v6_teid->teid;
  kv.value = sess - gtm->sessions;

  clib_warning("gtpdp_sx: is_add: %d, TEID: 0x%08x, IP:%U, Session:%p, idx: %p.",
	       is_add, v6_teid->teid,
	       format_ip6_address, &v6_teid->dst, sess,
	       sess - gtm->sessions);

  clib_bihash_add_del_24_8(&gtm->v6_tunnel_by_key, &kv, is_add);
}

/* Format an IP4 address. */
static u8 *format_ip4_address_host (u8 * s, va_list * args)
{
  u32 *a = va_arg (*args, u32 *);
  ip4_address_t ip4;

  ip4.as_u32 = clib_host_to_net_u32(*a);
  return format (s, "%d.%d.%d.%d", ip4.as_u8[0], ip4.as_u8[1], ip4.as_u8[2], ip4.as_u8[3]);
}

static u8 *
format_acl4 (u8 * s, va_list * args)
{
  struct acl4_rule *rule = va_arg (*args, struct acl4_rule *);

  s = format(s, "%U/%d %U/%d %hu : %hu %hu : %hu 0x%hhx/0x%hhx 0x%08x/0x%08x 0x%x-0x%x-0x%x",
	     format_ip4_address_host, &rule->field[SRC_FIELD_IPV4].value.u32,
	     rule->field[SRC_FIELD_IPV4].mask_range.u32,
	     format_ip4_address_host, &rule->field[DST_FIELD_IPV4].value.u32,
	     rule->field[DST_FIELD_IPV4].mask_range.u32,
	     rule->field[SRCP_FIELD_IPV4].value.u16,
	     rule->field[SRCP_FIELD_IPV4].mask_range.u16,
	     rule->field[DSTP_FIELD_IPV4].value.u16,
	     rule->field[DSTP_FIELD_IPV4].mask_range.u16,
	     rule->field[PROTO_FIELD_IPV4].value.u8,
	     rule->field[PROTO_FIELD_IPV4].mask_range.u8,
	     rule->field[GTP_TEID_IPV4].value.u32,
	     rule->field[GTP_TEID_IPV4].mask_range.u32,
	     rule->data.category_mask,
	     rule->data.priority,
	     rule->data.userdata);

  return s;
}

static u8 *
format_acl_ip6_address (u8 * s, va_list * args)
{
  struct rte_acl_field * field = va_arg (*args, struct rte_acl_field *);
  ip6_address_t addr;

  for (int i = 0; i < 4; i ++)
    addr.as_u32[i] = clib_host_to_net_u32(field[i].value.u32);

  return format(s, "%U", format_ip6_address, &addr);
}

static u8 *
format_acl6 (u8 * s, va_list * args)
{
  struct acl6_rule *rule = va_arg (*args, struct acl6_rule *);

  s = format(s, "%U/%u ",
	     format_acl_ip6_address, &rule->field[SRC1_FIELD_IPV6],
	     rule->field[SRC1_FIELD_IPV6].mask_range.u32
	     + rule->field[SRC2_FIELD_IPV6].mask_range.u32
	     + rule->field[SRC3_FIELD_IPV6].mask_range.u32
	     + rule->field[SRC4_FIELD_IPV6].mask_range.u32);

  s = format(s, "%U/%u ",
	     format_acl_ip6_address, &rule->field[DST1_FIELD_IPV6],
	     rule->field[DST1_FIELD_IPV6].mask_range.u32
	     + rule->field[DST2_FIELD_IPV6].mask_range.u32
	     + rule->field[DST3_FIELD_IPV6].mask_range.u32
	     + rule->field[DST4_FIELD_IPV6].mask_range.u32);

  s = format(s, "%hu : %hu %hu : %hu 0x%hhx/0x%hhx 0x%08x/0x%08x 0x%x-0x%x-0x%x",
	     rule->field[SRCP_FIELD_IPV6].value.u16,
	     rule->field[SRCP_FIELD_IPV6].mask_range.u16,
	     rule->field[DSTP_FIELD_IPV6].value.u16,
	     rule->field[DSTP_FIELD_IPV6].mask_range.u16,
	     rule->field[PROTO_FIELD_IPV6].value.u8,
	     rule->field[PROTO_FIELD_IPV6].mask_range.u8,
	     rule->field[GTP_TEID_IPV6].value.u32,
	     rule->field[GTP_TEID_IPV6].mask_range.u32,
	     rule->data.category_mask,
	     rule->data.priority,
	     rule->data.userdata);

  return s;
}

static int ipfilter_address_cmp_const(const ipfilter_address_t *a, const ipfilter_address_t b)
{
  int r;

  if ((r = intcmp(a->address.as_u64[0], b.address.as_u64[0])) != 0)
    return r;
  if ((r = intcmp(a->address.as_u64[1], b.address.as_u64[1])) != 0)
    return r;
  return intcmp(a->mask, b.mask);
}

static void rte_acl_set_port(struct rte_acl_field * field, const ipfilter_port_t * port)
{
  field->value.u16 = port->min;
  field->mask_range.u16 = port->max;
}

static void rte_acl_set_proto(struct rte_acl_field * field, u8 proto, u8 mask)
{
  field->value.u8 = proto;
  field->mask_range.u8 = mask;
}

static void acl_set_ue_ip4(struct acl4_rule *ip4, int field, const gtpdp_pdr_t *pdr)
{
  if ((pdr->pdi.fields & F_PDI_UE_IP_ADDR) &&
      pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_V4)
    {
      ip4->field[field].value.u32 = clib_net_to_host_u32(pdr->pdi.ue_addr.ip4.as_u32);
      ip4->field[field].mask_range.u32 = 32;
    }
  else
    {
      ip4->field[field].value.u32 = 0;
      ip4->field[field].mask_range.u32 = 0;
    }
}

static void ip4_assign_src_address(struct acl4_rule *ip4,
				   int field, const gtpdp_pdr_t *pdr)
{
  if (ipfilter_address_cmp_const(&pdr->pdi.acl.src_address, ACL_FROM_ANY) == 0)
    {
      ip4->field[field].value.u32 = 0;
      ip4->field[field].mask_range.u32 = 0;
    }
  else
    {
      ip4->field[field].value.u32 =
	clib_net_to_host_u32(pdr->pdi.acl.src_address.address.ip4.as_u32);
      ip4->field[field].mask_range.u32 = pdr->pdi.acl.src_address.mask;
    }
}

static void ip4_assign_dst_address(struct acl4_rule *ip4,
				   int field, const gtpdp_pdr_t *pdr)
{
  if (ipfilter_address_cmp_const(&pdr->pdi.acl.dst_address, ACL_TO_ASSIGNED) == 0)
    acl_set_ue_ip4(ip4, field, pdr);
  else
    {
      ip4->field[field].value.u32 =
	clib_net_to_host_u32(pdr->pdi.acl.dst_address.address.ip4.as_u32);
      ip4->field[field].mask_range.u32 = pdr->pdi.acl.dst_address.mask;
    }
}

static void ip4_assign_src_port(struct acl4_rule *ip4,
				int field, const gtpdp_pdr_t *pdr)
{
  rte_acl_set_port(&ip4->field[field], &pdr->pdi.acl.src_port);
}

static void ip4_assign_dst_port(struct acl4_rule *ip4,
				int field, const gtpdp_pdr_t *pdr)
{
  rte_acl_set_port(&ip4->field[field], &pdr->pdi.acl.dst_port);
}

static int add_ip4_sdf(struct rte_acl_ctx *ctx, const gtpdp_pdr_t *pdr,
		       u32 pdr_idx)
{
  struct acl4_rule r = {
    .data.userdata = pdr_idx + 1,	/* Idx could be 0, but rte_acl uses 0 as not found */
    .data.category_mask = -1,
    .data.priority = pdr->precedence,

    .field[GTP_TEID_IPV4] = {
      .value.u8 = 0,
      .mask_range.u8 = 0,
    },

    .field[PROTO_FIELD_IPV4] = {
      .value.u8 = pdr->pdi.acl.proto,
      .mask_range.u8 = ~0,
    },
  };

  if (pdr->pdi.acl.proto == (u8)~0)
    rte_acl_set_proto(&r.field[PROTO_FIELD_IPV4], 0, 0);

  if ((!acl_is_from_any(&pdr->pdi.acl.src_address) &&
       !ip46_address_is_ip4(&pdr->pdi.acl.src_address.address)) ||
      (!acl_is_to_assigned(&pdr->pdi.acl.dst_address) &&
       !ip46_address_is_ip4(&pdr->pdi.acl.dst_address.address)))
    return 0;

  switch (pdr->pdi.src_intf)
    {
    case SRC_INTF_ACCESS:
      ip4_assign_src_address(&r, DST_FIELD_IPV4, pdr);
      ip4_assign_dst_address(&r, SRC_FIELD_IPV4, pdr);
      ip4_assign_src_port(&r, DSTP_FIELD_IPV4, pdr);
      ip4_assign_dst_port(&r, SRCP_FIELD_IPV4, pdr);
      break;

    default:
      ip4_assign_src_address(&r, SRC_FIELD_IPV4, pdr);
      ip4_assign_dst_address(&r, DST_FIELD_IPV4, pdr);
      ip4_assign_src_port(&r, SRCP_FIELD_IPV4, pdr);
      ip4_assign_dst_port(&r, DSTP_FIELD_IPV4, pdr);
      break;
    }

  fformat(stderr, "PDR %d, IPv4 %s SDF (%p): %U\n", pdr->id,
	  (pdr->pdi.src_intf == SRC_INTF_ACCESS) ? "UL" : "DL",
	  ctx, format_acl4, &r);
  if (rte_acl_add_rules(ctx, (const struct rte_acl_rule *)&r, 1) < 0)
    rte_exit(EXIT_FAILURE, "IP6 add rules failed\n");

  return 0;
}

static u32 ip6_mask (u8 pos, u8 pref_len)
{
  if ((4 - pos) > (pref_len / 32))
    return 0;
  else if ((4 - pos) < (pref_len / 32))
    return 32;
  else
    return pref_len % 32;
}

static void acl_set_ue_ip6(struct acl6_rule *ip6, int field, const gtpdp_pdr_t *pdr)
{
  if ((pdr->pdi.fields & F_PDI_UE_IP_ADDR) &&
      pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_V6)
    for (int i = 0; i < 4; i++)
      {
	ip6->field[field + i].value.u32 = clib_net_to_host_u32(pdr->pdi.ue_addr.ip6.as_u32[i]);
	ip6->field[field + i].mask_range.u32 = ~0;
      }
  else
    for (int i = 0; i < 4; i++)
      {
	ip6->field[field + i].value.u32 = 0;
	ip6->field[field + i].mask_range.u32 = 0;
      }
}

static void ip6_assign_src_address(struct acl6_rule *ip6,
				   int field, const gtpdp_pdr_t *pdr)
{
  if (ipfilter_address_cmp_const(&pdr->pdi.acl.src_address, ACL_FROM_ANY) == 0)
    for (int i = 0; i < 4; i++)
      {
	ip6->field[field + i].value.u32 = 0;
	ip6->field[field + i].mask_range.u32 = 0;
      }
  else
    for (int i = 0; i < 4; i++)
      {
	ip6->field[field + i].value.u32 =
	  clib_net_to_host_u32(pdr->pdi.acl.src_address.address.ip6.as_u32[i]);
	ip6->field[field + i].mask_range.u32 = ip6_mask(i, pdr->pdi.acl.src_address.mask);
      }
}

static void ip6_assign_dst_address(struct acl6_rule *ip6,
				   int field, const gtpdp_pdr_t *pdr)
{
  if (ipfilter_address_cmp_const(&pdr->pdi.acl.dst_address, ACL_TO_ASSIGNED) == 0)
    acl_set_ue_ip6(ip6, field, pdr);
  else
    for (int i = 0; i < 4; i++)
      ip6->field[field + i] = (struct rte_acl_field){
	.value.u32 = clib_net_to_host_u32(pdr->pdi.acl.dst_address.address.ip6.as_u32[i]),
	.mask_range.u32 = ip6_mask(i, pdr->pdi.acl.dst_address.mask),
      };
}

static void ip6_assign_src_port(struct acl6_rule *ip6,
				int field, const gtpdp_pdr_t *pdr)
{
  rte_acl_set_port(&ip6->field[field], &pdr->pdi.acl.src_port);
}

static void ip6_assign_dst_port(struct acl6_rule *ip6,
				int field, const gtpdp_pdr_t *pdr)
{
  rte_acl_set_port(&ip6->field[field], &pdr->pdi.acl.dst_port);
}

static int add_ip6_sdf(struct rte_acl_ctx *ctx, const gtpdp_pdr_t *pdr,
		       u32 pdr_idx)
{
  struct acl6_rule r = {
    .data.userdata = pdr_idx + 1,	/* Idx could be 0, but rte_acl uses 0 as not found */
    .data.category_mask = -1,
    .data.priority = pdr->precedence,

    .field[GTP_TEID_IPV6] = {
      .value.u32 = 0,
      .mask_range.u32 = 0,
    },

    .field[PROTO_FIELD_IPV6] = {
      .value.u8 = pdr->pdi.acl.proto,
      .mask_range.u8 = ~0,
    },
  };

  if (pdr->pdi.acl.proto == (u8)~0)
    rte_acl_set_proto(&r.field[PROTO_FIELD_IPV6], 0, 0);

  if ((!acl_is_from_any(&pdr->pdi.acl.src_address) &&
       ip46_address_is_ip4(&pdr->pdi.acl.src_address.address)) ||
      (!acl_is_to_assigned(&pdr->pdi.acl.dst_address) &&
       ip46_address_is_ip4(&pdr->pdi.acl.dst_address.address)))
    return 0;

  switch (pdr->pdi.src_intf)
    {
    case SRC_INTF_ACCESS:
      ip6_assign_src_address(&r, DST1_FIELD_IPV6, pdr);
      ip6_assign_dst_address(&r, SRC1_FIELD_IPV6, pdr);
      ip6_assign_src_port(&r, DSTP_FIELD_IPV6, pdr);
      ip6_assign_dst_port(&r, SRCP_FIELD_IPV6, pdr);
      break;

    default:
      ip6_assign_src_address(&r, SRC1_FIELD_IPV6, pdr);
      ip6_assign_dst_address(&r, DST1_FIELD_IPV6, pdr);
      ip6_assign_src_port(&r, SRCP_FIELD_IPV6, pdr);
      ip6_assign_dst_port(&r, DSTP_FIELD_IPV6, pdr);
      break;
    }

  fformat(stderr, "PDR %d, IPv6 %s SDF (%p): %U\n", pdr->id,
	  (pdr->pdi.src_intf == SRC_INTF_ACCESS) ? "UL" : "DL",
	  ctx, format_acl6, &r);
  if (rte_acl_add_rules(ctx, (const struct rte_acl_rule *)&r, 1) < 0)
    rte_exit(EXIT_FAILURE, "IP6 add rules failed\n");

  return 0;
}

static int add_wildcard_teid(struct rules *rules, const pfcp_f_teid_t teid, u32 pdr_id)
{
  if (teid.flags & F_TEID_V4)
    {
      gtpu4_tunnel_key_t v4_teid;

      v4_teid.dst = teid.ip4.as_u32;
      v4_teid.teid = teid.teid;

      hash_set (rules->v4_wildcard_teid, v4_teid.as_u64, pdr_id);
    }

  if (teid.flags & F_TEID_V6)
    {
      gtpu6_tunnel_key_t v6_teid;

      v6_teid.dst = teid.ip6;
      v6_teid.teid = teid.teid;

      if (!rules->v6_wildcard_teid)
	rules->v6_wildcard_teid = hash_create_mem (0,
						   sizeof (gtpu6_tunnel_key_t),
						   sizeof (uword));

      hash_set_mem_alloc (&rules->v6_wildcard_teid, &v6_teid, pdr_id);
    }

  return 0;
}

static int add_wildcard_ip4_sdf(struct rte_acl_ctx *ctx, const gtpdp_pdr_t *pdr,
				u32 pdr_idx)
{
  struct acl4_rule r = {
    .data.userdata = pdr_idx + 1,	/* Idx could be 0, but rte_acl uses 0 as not found */
    .data.category_mask = -1,
    .data.priority = pdr->precedence,

    .field[GTP_TEID_IPV4]    = {.value.u32 = 0, .mask_range.u32 = 0,},
    .field[PROTO_FIELD_IPV4] = {.value.u8 = 0, .mask_range.u8 = 0,},
    .field[SRC_FIELD_IPV4]   = {.value.u32 = 0, .mask_range.u32 = 0,},
    .field[DST_FIELD_IPV4]   = {.value.u32 = 0, .mask_range.u32 = 0,},
    .field[SRCP_FIELD_IPV4]  = {.value.u16 = 0, .mask_range.u16 = 0xffff,},
    .field[DSTP_FIELD_IPV4]  = {.value.u16 = 0, .mask_range.u16 = 0xffff,},
  };

  switch (pdr->pdi.src_intf)
    {
    case SRC_INTF_ACCESS:
      acl_set_ue_ip4(&r, DST_FIELD_IPV4, pdr);
      break;

    default:
      acl_set_ue_ip4(&r, SRC_FIELD_IPV4, pdr);
      break;
    }

  fformat(stderr, "PDR %d, IPv4 %s wildcard SDF (%p): %U\n", pdr->id,
	  (pdr->pdi.src_intf == SRC_INTF_ACCESS) ? "UL" : "DL",
	  ctx, format_acl4, &r);
  if (rte_acl_add_rules(ctx, (const struct rte_acl_rule *)&r, 1) < 0)
    rte_exit(EXIT_FAILURE, "IP4 add rules failed\n");

    return 0;
}

static int add_wildcard_ip6_sdf(struct rte_acl_ctx *ctx, const gtpdp_pdr_t *pdr,
				u32 pdr_idx)
{
  struct acl6_rule r = {
    .data.userdata = pdr_idx + 1,	/* Idx could be 0, but rte_acl uses 0 as not found */
    .data.category_mask = -1,
    .data.priority = pdr->precedence,

    .field[GTP_TEID_IPV6]    = {.value.u32 = 0, .mask_range.u32 = 0,},
    .field[PROTO_FIELD_IPV6] = {.value.u8 = 0, .mask_range.u8 = 0,},
    .field[SRC1_FIELD_IPV6]  = {.value.u32 = 0,. mask_range.u32 = 0,},
    .field[SRC2_FIELD_IPV6]  = {.value.u32 = 0,. mask_range.u32 = 0,},
    .field[SRC3_FIELD_IPV6]  = {.value.u32 = 0,. mask_range.u32 = 0,},
    .field[SRC4_FIELD_IPV6]  = {.value.u32 = 0,. mask_range.u32 = 0,},
    .field[DST1_FIELD_IPV6]  = {.value.u32 = 0,. mask_range.u32 = 0,},
    .field[DST2_FIELD_IPV6]  = {.value.u32 = 0,. mask_range.u32 = 0,},
    .field[DST3_FIELD_IPV6]  = {.value.u32 = 0,. mask_range.u32 = 0,},
    .field[DST4_FIELD_IPV6]  = {.value.u32 = 0,. mask_range.u32 = 0,},
    .field[SRCP_FIELD_IPV6]  = {.value.u16 = 0, .mask_range.u16 = 0xffff,},
    .field[DSTP_FIELD_IPV6]  = {.value.u16 = 0, .mask_range.u16 = 0xffff,},
  };

  switch (pdr->pdi.src_intf)
    {
    case SRC_INTF_ACCESS:
      acl_set_ue_ip6(&r, DST1_FIELD_IPV6, pdr);
      break;

    default:
      acl_set_ue_ip6(&r, SRC1_FIELD_IPV6, pdr);
      break;
    }

  fformat(stderr, "PDR %d, IPv6 %s wildcard SDF (%p): %U\n", pdr->id,
	  (pdr->pdi.src_intf == SRC_INTF_ACCESS) ? "UL" : "DL",
	  ctx, format_acl6, &r);
  if (rte_acl_add_rules(ctx, (const struct rte_acl_rule *)&r, 1) < 0)
    rte_exit(EXIT_FAILURE, "IP6 add rules failed\n");

  return 0;
}

static int sx_acl_create(u64 cp_f_seid, struct rules *rules, int direction)
{
  /*
   * Check numa socket enable or disable based on
   * get or set socketid.
   */
  gtpdp_acl_ctx_t *ctx = &rules->sdf[direction];

  char name[RTE_ACL_NAMESIZE];
  struct rte_acl_param ip4acl = {
    .name = name,
    .socket_id = 0,
    .rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv4_defs)),
    .max_rule_num = vec_len(rules->pdr),
  };

  struct rte_acl_param ip6acl = {
    .name = name,
    .socket_id = 0,
    .rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv6_defs)),
    .max_rule_num = vec_len(rules->pdr),
  };

  if (rules->flags & SX_SDF_IPV4)
    {
      snprintf(name, sizeof(name), "sx_%"PRIu64"_sdf_ip4_%d",
	       cp_f_seid, direction);
      ctx->ip4 = rte_acl_create(&ip4acl);
      if (!ctx->ip4)
	rte_exit(EXIT_FAILURE, "Failed to create ACL context\n");
    }

  if (rules->flags & SX_SDF_IPV6)
    {
      snprintf(name, sizeof(name), "sx_%"PRIu64"_sdf_ip6_%d",
	       cp_f_seid, direction);
      ctx->ip6 = rte_acl_create(&ip6acl);
      if (!ctx->ip6)
	rte_exit(EXIT_FAILURE, "Failed to create ACL context\n");
    }
  return 0;
}

static int sx_acl_build(struct rules *rules, int direction)
{
  gtpdp_acl_ctx_t *ctx = &rules->sdf[direction];

  if (ctx->ip4)
    {
      struct rte_acl_config cfg = {
	.num_categories = 1,
	.num_fields = RTE_DIM(ipv4_defs),
      };
      memcpy(&cfg.defs, ipv4_defs, sizeof(ipv4_defs));

      /* Perform builds */
      if (rte_acl_build(ctx->ip4, &cfg) != 0)
	{
	  // TODO: ctx without rules will fail, find some other way to handle that
	  clib_warning("RTE ACL %s IPv4 build failed, no need to worry!",
		       direction == UL_SDF ? "UL" : "DL");
	  rte_acl_free(ctx->ip4);
	  ctx->ip4 = NULL;
	}
      else
	{
	  clib_warning("RTE ACL %s IPv4 build SUCCEEDED!",
		       direction == UL_SDF ? "UL" : "DL");
	  rte_acl_dump(ctx->ip4);
	}
    }

  if (ctx->ip6)
    {
      struct rte_acl_config cfg = {
	.num_categories = 1,
	.num_fields = RTE_DIM(ipv6_defs),
      };
      memcpy(&cfg.defs, ipv6_defs, sizeof(ipv6_defs));

      /* Perform builds */
      if (rte_acl_build(ctx->ip6, &cfg) != 0)
	{
	  // TODO: ctx without rules will fail, find some other way to handle that
	  clib_warning("RTE ACL %s IPv6 build failed, no need to worry!",
		       direction == UL_SDF ? "UL" : "DL");
	  rte_acl_free(ctx->ip6);
	  ctx->ip6 = NULL;
	}
      else
	{
	  rte_acl_dump(ctx->ip6);
	  clib_warning("RTE ACL %s IPv6 build SUCCEEDED!",
		       direction == UL_SDF ? "UL" : "DL");
	}
    }
  return 0;
}

static void sx_acl_free(gtpdp_acl_ctx_t *ctx)
{
  rte_acl_free(ctx->ip4);
  rte_acl_free(ctx->ip6);
}

static void rules_add_v4_teid(struct rules * r, const ip4_address_t * addr, u32 teid)
{
  gtpu4_tunnel_key_t key;

  key.teid = teid;
  key.dst = addr->as_u32;

  vec_add1(r->v4_teid, key);
}

static void rules_add_v6_teid(struct rules * r, const ip6_address_t * addr, u32 teid)
{
  gtpu6_tunnel_key_t key;

  key.teid = teid;
  key.dst = *addr;

  vec_add1(r->v6_teid, key);
}

#define sdf_src_address_type(acl)					\
  ipfilter_address_cmp_const(&(acl)->src_address, ACL_FROM_ANY) == 0	\
    ? 0 :								\
    (ip46_address_is_ip4(&(acl)->src_address.address) ? SX_SDF_IPV4 : SX_SDF_IPV6)

#define sdf_dst_address_type(acl)					\
  ipfilter_address_cmp_const(&(acl)->dst_address, ACL_TO_ASSIGNED) == 0	\
    ? 0 :								\
    (ip46_address_is_ip4(&(acl)->dst_address.address) ? SX_SDF_IPV4 : SX_SDF_IPV6)

static int build_sx_sdf(gtpdp_session_t *sx)
{
  struct rules *pending = sx_get_rules(sx, SX_PENDING);
  uint64_t cp_f_seid = sx->cp_f_seid;
  gtpdp_pdr_t *pdr;

  pending->flags &= ~(SX_SDF_IPV4 | SX_SDF_IPV6);

  vec_foreach (pdr, pending->pdr) {
    printf("PDR Scan: %d\n", pdr->id);

    if (pdr->pdi.fields & F_PDI_UE_IP_ADDR)
      {
	ip46_address_fib_t *vrf_ip;

	if (pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_V4)
	  {
	    pending->flags |= SX_SDF_IPV4;

	    vec_alloc(pending->vrf_ip, 1);
	    vrf_ip = vec_end(pending->vrf_ip);
	    ip46_address_set_ip4(&vrf_ip->addr, &pdr->pdi.ue_addr.ip4);
	    vrf_ip->fib_index = 0;

/* TODO: nw instance
	if (pdr->pdi.fields & F_PDI_NW_INSTANCE)
	  vrf_ip->fib_index = pdr->pdi.nw_instance;
*/

	    _vec_len(pending->vrf_ip)++;
	  }

	if (pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_V6)
	  {
	    pending->flags |= SX_SDF_IPV6;

	    vec_alloc(pending->vrf_ip, 1);
	    vrf_ip = vec_end(pending->vrf_ip);
	    vrf_ip->addr.ip6 = pdr->pdi.ue_addr.ip6;
	    vrf_ip->fib_index = 0;

/* TODO: nw instance
	if (pdr->pdi.fields & F_PDI_NW_INSTANCE)
	  vrf_ip->fib_index = pdr->pdi.nw_instance;
*/

	    _vec_len(pending->vrf_ip)++;
	  }
      }

    if (pdr->pdi.fields & F_PDI_SDF_FILTER)
      {
	pending->flags |= sdf_src_address_type(&pdr->pdi.acl);
	pending->flags |= sdf_dst_address_type(&pdr->pdi.acl);
      }

    if (pdr->pdi.fields & F_PDI_LOCAL_F_TEID)
      {
	if (pdr->pdi.teid.flags & F_TEID_V4)
	  rules_add_v4_teid(pending, &pdr->pdi.teid.ip4, pdr->pdi.teid.teid);

	if (pdr->pdi.teid.flags & F_TEID_V6)
	  rules_add_v6_teid(pending, &pdr->pdi.teid.ip6, pdr->pdi.teid.teid);
      }
  }
  if (vec_len(pending->pdr) == 0)
    return 0;

  sx_acl_create(cp_f_seid, pending, UL_SDF);
  sx_acl_create(cp_f_seid, pending, DL_SDF);

  vec_foreach (pdr, pending->pdr)
    {
      int direction = (pdr->pdi.src_intf == SRC_INTF_ACCESS) ? UL_SDF : DL_SDF;
      gtpdp_acl_ctx_t *ctx = &pending->sdf[direction];

      if (!(pdr->pdi.fields & F_PDI_SDF_FILTER))
	{
	  if ((pdr->pdi.fields & F_PDI_LOCAL_F_TEID) &&
	      !(pdr->pdi.fields & F_PDI_UE_IP_ADDR))
	    add_wildcard_teid(pending, pdr->pdi.teid, pdr->id);

	  if (pdr->pdi.src_intf != SRC_INTF_ACCESS &&
	      !(pdr->pdi.fields & F_PDI_UE_IP_ADDR))
	    /* wildcard DL SDF only if UE IP is set */
	    continue;

	  if (pending->flags & SX_SDF_IPV4)
	    add_wildcard_ip4_sdf(ctx->ip4, pdr, pdr - pending->pdr);
	  if (pending->flags & SX_SDF_IPV6)
	    add_wildcard_ip6_sdf(ctx->ip6, pdr, pdr - pending->pdr);
	  continue;
	}

      if (pending->flags & SX_SDF_IPV4)
	if (add_ip4_sdf(ctx->ip4, pdr, pdr - pending->pdr) < 0)
	  return -1;
      if (pending->flags & SX_SDF_IPV6)
	if (add_ip6_sdf(ctx->ip6, pdr, pdr - pending->pdr) < 0)
	  return -1;
    }

  sx_acl_build(pending, UL_SDF);
  sx_acl_build(pending, DL_SDF);

  return 0;
}

int sx_update_apply(gtpdp_session_t *sx)
{
  struct rules *pending = sx_get_rules(sx, SX_PENDING);
  struct rules *active = sx_get_rules(sx, SX_ACTIVE);
  int pending_pdr, pending_far, pending_urr;

  if (!pending->pdr && !pending->far && !pending->urr)
    return 0;

  pending_pdr = !!pending->pdr;
  pending_far = !!pending->far;
  pending_urr = !!pending->urr;

  if (pending_pdr)
    {
      if (build_sx_sdf(sx) != 0)
	return -1;
    }
  else
    {
      pending->pdr = active->pdr;

      pending->vrf_ip = active->vrf_ip;
      active->vrf_ip = NULL;

      pending->v4_teid = active->v4_teid;
      active->v4_teid = NULL;
      pending->v6_teid = active->v6_teid;
      active->v6_teid = NULL;

      pending->v4_wildcard_teid = active->v4_wildcard_teid;
      active->v4_wildcard_teid = NULL;

      pending->v6_wildcard_teid = active->v6_wildcard_teid;
      active->v6_wildcard_teid = NULL;

      memcpy(&pending->sdf, &active->sdf, sizeof(active->sdf));
      memset(&active->sdf, 0, sizeof(active->sdf));

      pending->flags = active->flags;
    }

  if (pending->far)
    {
      gtpdp_far_t *far;

      vec_foreach (far, pending->far)
	if (far->forward.outer_header_creation != 0)
	  {
	    far->forward.peer_idx = peer_addr_ref(&far->forward.addr, far->forward.nwi);

	    switch (far->forward.outer_header_creation)
	      {
	      case GTP_U_UDP_IPv4:
		rules_add_v4_teid(pending, &far->forward.addr.ip4, far->forward.teid);
		break;

	      case GTP_U_UDP_IPv6:
		rules_add_v6_teid(pending, &far->forward.addr.ip6, far->forward.teid);
		break;
	      }
	  }
    }
  else
    pending->far = active->far;

  if (pending_urr)
    {
      gtpdp_urr_t *urr;

      vec_foreach (urr, pending->urr)
	vlib_validate_combined_counter(&urr->measurement.volume, URR_COUNTER_NUM);
    }
  else
    pending->urr = active->urr;

  if (pending_pdr)
    {
      sx->flags |= SX_UPDATING;

      /* make sure all processing nodes see the update op */
      synchronize_rcu();

      /* update UE addresses and TEIDs */
      vec_diff(pending->vrf_ip, active->vrf_ip, ip46_address_fib_cmp,
	       sx_add_del_vrf_ip, sx);
      vec_diff(pending->v4_teid, active->v4_teid, v4_teid_cmp, sx_add_del_v4_teid, sx);
      vec_diff(pending->v6_teid, active->v6_teid, v6_teid_cmp, sx_add_del_v6_teid, sx);

      // TODO: add SDF rules to global table
    }

  /* flip the switch */
  sx->active ^= SX_PENDING;
  sx->flags &= ~SX_UPDATING;

  if (pending->send_end_marker)
    {
      u16 * send_em;

      vec_foreach (send_em, pending->send_end_marker)
	{
	  gtpdp_far_t *far;
	  gtpdp_far_t r = { .id = *send_em };

	  if (!(far = vec_bsearch(&r, active->far, sx_far_id_compare)))
	    continue;

	  clib_warning("TODO: send_end_marker for FAR %d", far->id);
	  gtpu_send_end_marker(&far->forward);
	}
      vec_free(pending->send_end_marker);
    }

  pending = sx_get_rules(sx, SX_PENDING);
  if (!pending_pdr) pending->pdr = NULL;
  if (!pending_far) pending->far = NULL;
  if (!pending_urr) pending->urr = NULL;

  return 0;
}

void sx_update_finish(gtpdp_session_t *sx)
{
  sx_free_rules(sx, SX_PENDING);
}

/******************** Sx Session functions **********************/

/**
 * @brief Function to return session info entry address.
 *
 */
gtpdp_session_t *sx_lookup(uint64_t sess_id)
{
  gtpdp_main_t *gtm = &gtpdp_main;
  uword *p;

  p = hash_get (gtm->session_by_id, sess_id);
  if (!p)
    return NULL;

  return pool_elt_at_index (gtm->sessions, p[0]);
}

void
vlib_free_combined_counter (vlib_combined_counter_main_t * cm)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  int i;

  for (i = 0; i < tm->n_vlib_mains; i++)
    vec_free (cm->counters[i]);
  vec_free (cm->counters);
}

void process_urrs(vlib_main_t *vm, struct rules *r,
		  gtpdp_pdr_t *pdr, vlib_buffer_t * b,
		  u8 is_dl, u8 is_ul)
{
  u32 thread_index = vlib_get_thread_index ();
  u16 *urr_id;

  vec_foreach (urr_id, pdr->urr_ids)
    {
      gtpdp_urr_t * urr = sx_get_urr_by_id(r, *urr_id);

      if (!urr)
	continue;

      if (urr->methods & SX_URR_VOLUME)
	{
	  if (is_dl)
	    vlib_increment_combined_counter(&urr->measurement.volume, thread_index,
					    URR_COUNTER_DL, 1,
					    vlib_buffer_length_in_chain (vm, b));
	  if (is_ul)
	    vlib_increment_combined_counter(&urr->measurement.volume, thread_index,
					    URR_COUNTER_UL, 1,
					    vlib_buffer_length_in_chain (vm, b));
	  vlib_increment_combined_counter(&urr->measurement.volume, thread_index,
					  URR_COUNTER_TOTAL, 1,
					  vlib_buffer_length_in_chain (vm, b));
	}
    }
}

static u8 *
format_flags(u8 * s, va_list * args)
{
  uint64_t flags = va_arg (*args, uint64_t);
  const char **atoms = va_arg (*args, char **);
  int first = 1;

  s = format(s, "[");
  for (int i = 0; i < 64 && atoms[i] != NULL; i++) {
    if (!ISSET_BIT(flags, i))
      continue;

    if (!first)
      s = format(s, ",");

    s = format(s, "%s", atoms[i]);
    first = 0;
  }
  s = format(s, "]");

  return s;
}

static const char *apply_action_flags[] = {
  "DROP",
  "FORWARD",
  "BUFFER",
  "NOTIFY_CP",
  "DUPLICATE",
  NULL
};

static const char *urr_method_flags[] = {
  "TIME",
  "VOLUME",
  "EVENT",
  NULL
};

u8 *
format_sx_session(u8 * s, va_list * args)
{
  gtpdp_session_t *sx = va_arg (*args, gtpdp_session_t *);
  int rule = va_arg (*args, int);
  struct rules *rules = sx_get_rules(sx, rule);
  gtpdp_main_t *gtm = &gtpdp_main;
  gtpdp_pdr_t *pdr;
  gtpdp_far_t *far;
  gtpdp_urr_t *urr;

  s = format(s, "CP F-SEID: %" PRIu64 " @ %p\n"
	     "Active: %u\nPending: %u\n",
	     sx->cp_f_seid, sx,
	     sx->active ^ SX_ACTIVE, sx->active ^ SX_PENDING);

  s = format(s, "PDR: %p\nFAR: %p\n",
	     rules->pdr, rules->far);

  vec_foreach (pdr, rules->pdr) {
    gtpdp_nwi_t * nwi = NULL;
    size_t j;

    if (!pool_is_free_index (gtm->nwis, pdr->pdi.nwi))
      nwi = pool_elt_at_index (gtm->nwis, pdr->pdi.nwi);

    s = format(s, "PDR: %u @ %p\n"
	       "  Precedence: %u\n"
	       "  PDI:\n"
	       "    Fields: %08x\n",
	       pdr->id, pdr,
	       pdr->precedence,
	       pdr->pdi.fields);

    s = format(s, "    Network Instance: %U\n",
	       format_network_instance, nwi ? nwi->name : NULL);

    if (pdr->pdi.fields & F_PDI_LOCAL_F_TEID)
      {
	s = format(s, "    Local F-TEID: %u (0x%08x)\n",
		   pdr->pdi.teid.teid, pdr->pdi.teid.teid);
	if (pdr->pdi.teid.flags & F_TEID_V4)
	  s = format(s, "            IPv4: %U\n",
		     format_ip4_address, &pdr->pdi.teid.ip4);
	if (pdr->pdi.teid.flags & F_TEID_V6)
	  s = format(s, "            IPv6: %U\n",
		     format_ip6_address, &pdr->pdi.teid.ip6);
      }
    if (pdr->pdi.fields & F_PDI_UE_IP_ADDR)
      {
	s = format(s, "    UE IP address:\n");
	if (pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_V4)
	  s = format(s, "      IPv4 address: %U\n",
		     format_ip4_address, &pdr->pdi.ue_addr.ip4);
	if (pdr->pdi.ue_addr.flags & IE_UE_IP_ADDRESS_V6)
	  s = format(s, "      IPv6 address: %U\n",
		     format_ip6_address, &pdr->pdi.ue_addr.ip6);
      }
    if (pdr->pdi.fields & F_PDI_SDF_FILTER) {
      s = format(s, "    SDF Filter:\n");
      s = format(s, "      %U\n", format_ipfilter, &pdr->pdi.acl);
    }
    s = format(s, "  Outer Header Removal: %u\n"
	       "  FAR Id: %u\n"
	       "  URR Ids: [",
	       pdr->outer_header_removal, pdr->far_id);
    vec_foreach_index (j, pdr->urr_ids)
      s = format(s, "%s%u", j != 0 ? ":" : "", vec_elt(pdr->urr_ids, j));
    s = format(s, "] @ %p\n", pdr->urr_ids);
  }

  vec_foreach (far, rules->far) {
    gtpdp_nwi_t * nwi = NULL;

    if (!pool_is_free_index (gtm->nwis, far->forward.nwi))
      nwi = pool_elt_at_index (gtm->nwis, far->forward.nwi);

    s = format(s, "FAR: %u\n"
	       "  Apply Action: %08x == %U\n",
	       far->id, far->apply_action,
	       format_flags, far->apply_action, apply_action_flags);

    if (far->apply_action & FAR_FORWARD) {
      s = format(s, "  Forward:\n"
		 "    Network Instance: %U\n"
		 "    Destination Interface: %u\n"
		 "    Outer Header Creation: %u\n",
		 format_network_instance, nwi ? nwi->name : NULL,
		 far->forward.dst_intf, far->forward.outer_header_creation);
      switch (far->forward.outer_header_creation) {
      case GTP_U_UDP_IPv4:
      case GTP_U_UDP_IPv6:
	s = format(s, "    FQ-TEID: %U:0x%08x\n",
		   format_ip46_address, &far->forward.addr, IP46_TYPE_ANY,
		   far->forward.teid);
	break;
      default:
	break;
      }
    }
  }

  vec_foreach (urr, rules->urr)
    s = format(s, "URR: %u\n"
	       "  Measurement Method: %04x == %U\n",
	       urr->id, urr->methods,
	       format_flags, urr->methods, urr_method_flags);

  return s;
}

void sx_session_dump_tbls()
{
#if 0
	//TODO: implement
	const void *next_key;
	void *next_data;
	uint32_t iter;

	printf("Sx Session Hash:\n");
	iter = 0;
	while (rte_hash_iterate(rte_sx_hash, &next_key, &next_data, &iter) >= 0)
		printf("  CP F-SEID: %" PRIu64 " @ %p\n", *(uint64_t *)next_key, next_data);

	printf("Sx TEID Hash:\n");
	iter = 0;
	while (rte_hash_iterate(rte_sx_teid_hash, &next_key, &next_data, &iter) >= 0)
		printf("  CP F-SEID: %u (0x%08x) @ %p\n",
		       *(uint32_t *)next_key, *(uint32_t *)next_key, next_data);
#endif
}
