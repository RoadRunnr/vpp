/*
 * Copyright (c) 2018 Travelping GmbH
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
 */

#define _LGPL_SOURCE            /* LGPL v3.0 is compatible with Apache 2.0 */
#include <urcu-qsbr.h>          /* QSBR RCU flavor */

#include <rte_config.h>
#include <rte_common.h>
#include <rte_acl.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <gtpdp/gtpdp.h>
#include <gtpdp/gtpdp_sx.h>

/* Statistics (not all errors) */
#define foreach_gtpdp_classify_error    \
_(CLASSIFY, "good packets classify")

static char * gtpdp_classify_error_strings[] = {
#define _(sym,string) string,
  foreach_gtpdp_classify_error
#undef _
};

typedef enum {
#define _(sym,str) GTPDP_CLASSIFY_ERROR_##sym,
    foreach_gtpdp_classify_error
#undef _
    GTPDP_CLASSIFY_N_ERROR,
} gtpdp_classify_error_t;

#define foreach_gtpdp_classify_next	\
  _(DROP, "error-drop")			\
  _(GTPDP4_ENCAP, "gtpdp4-encap")       \
  _(GTPDP6_ENCAP, "gtpdp6-encap")	\
  _(IP4_INPUT, "ip4-input")		\
  _(IP6_INPUT, "ip6-input")

typedef enum {
  GTPDP_CLASSIFY_NEXT_DROP,
  GTPDP_CLASSIFY_NEXT_GTPDP4_ENCAP,
  GTPDP_CLASSIFY_NEXT_GTPDP6_ENCAP,
  GTPDP_CLASSIFY_NEXT_IP4_INPUT,
  GTPDP_CLASSIFY_NEXT_IP6_INPUT,
  GTPDP_CLASSIFY_N_NEXT,
} gtpdp_classify_next_t;

typedef struct {
  u32 session_index;
  u64 cp_f_seid;
  u32 pdr_id;
  u8 packet_data[64 - 1 * sizeof (u32)];
} gtpdp_classify_trace_t;

u8 * format_gtpdp_classify_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gtpdp_classify_trace_t * t
    = va_arg (*args, gtpdp_classify_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "gtpdp_session%d seid %d pdr %d\n%U%U",
	      t->session_index, t->cp_f_seid, t->pdr_id,
	      format_white_space, indent,
	      format_ip4_header, t->packet_data, sizeof (t->packet_data));
  return s;
}

static uword
gtpdp_classify (vlib_main_t * vm, vlib_node_runtime_t * node,
		vlib_frame_t * from_frame, int is_ip4)
{
  u32 n_left_from, next_index, * from, * to_next;
  gtpdp_main_t * gtm = &gtpdp_main;
  vnet_main_t * vnm = gtm->vnet_main;
  vnet_interface_main_t * im = &vnm->interface_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  u32 thread_index = vlib_get_thread_index();
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;
  u32 sw_if_index = 0;
  u32 next = 0;
  gtpdp_session_t * sess = NULL;
  u32 sidx = 0;
  u32 len;
  struct rules *active;
  ip4_header_t *ip4;
  ip6_header_t *ip6;
  struct rte_acl_ctx *acl;
  uint32_t results[1]; /* make classify by 4 categories. */
  const u8 *data[4];

  next_index = node->cached_next_index;
  stats_sw_if_index = node->runtime_data[0];
  stats_n_packets = stats_n_bytes = 0;

  while (n_left_from > 0)
    {
      gtpdp_pdr_t * pdr = NULL;
      gtpdp_far_t * far = NULL;
      u32 n_left_to_next;
      vlib_buffer_t * b;
      u8 direction;
      u8 * pl;
      u32 bi;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  bi = from[0];
	  to_next[0] = bi;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b = vlib_get_buffer (vm, bi);

	  /* Get next node index and adj index from tunnel next_dpo */
	  sidx = vnet_buffer (b)->gtpu.session_index;
	  sess = pool_elt_at_index (gtm->sessions, sidx);

	  next = GTPDP_CLASSIFY_NEXT_DROP;
	  active = sx_get_rules(sess, SX_ACTIVE);
	  direction = vnet_buffer (b)->gtpu.src_intf == INTF_ACCESS ? UL_SDF : DL_SDF;

	  pl = vlib_buffer_get_current(b) + vnet_buffer (b)->gtpu.data_offset;

	  acl = is_ip4 ? active->sdf[direction].ip4 : active->sdf[direction].ip6;
	  if (acl == NULL)
	    {
	      uword *p;

	      if (is_ip4)
		{
		  ip4 = (ip4_header_t *)vlib_buffer_get_current(b);
		  gtpu4_tunnel_key_t key4;

		  key4.dst = ip4->dst_address.as_u32;
		  key4.teid = vnet_buffer (b)->gtpu.teid;

		  p = hash_get (active->v4_wildcard_teid, key4.as_u64);
		}
	      else
		{
		  ip6 = (ip6_header_t *)vlib_buffer_get_current(b);
		  gtpu6_tunnel_key_t key6;

		  key6.dst.as_u64[0] = ip6->dst_address.as_u64[0];
		  key6.dst.as_u64[1] = ip6->dst_address.as_u64[1];
		  key6.teid = vnet_buffer (b)->gtpu.teid;

		  p = hash_get_mem (active->v6_wildcard_teid, &key6);
		}

	      if (PREDICT_TRUE (p != NULL))
		{
		  pdr = sx_get_pdr_by_id(active, p[0]);
		  if (PREDICT_TRUE (pdr != NULL))
		    far = sx_get_far_by_id(active, pdr->far_id);
		}
	    }
	  else
	    {
	      u32 save, *teid;

	      data[0] = pl;

	      /* append TEID to data */
	      teid = (u32 *)(pl + (is_ip4 ? sizeof(ip4_header_t) : sizeof(ip6_header_t))
			     + sizeof(udp_header_t));
	      save = *teid;
	      *teid = vnet_buffer (b)->gtpu.teid;

	      if (is_ip4)
		{
		  ip4 = (ip4_header_t *)pl;

		  rte_acl_classify(acl, data, results, 1, 1);
		  clib_warning("Ctx: %p, src: %U, dst %U, r: %d\n",
			       acl,
			       format_ip4_address, &ip4->src_address,
			       format_ip4_address, &ip4->dst_address,
			       results[0]);
		  if (PREDICT_TRUE (results[0] != 0))
		    {
		      vnet_buffer (b)->gtpu.pdr_idx = results[0] - 1;

		      /* TODO: this should be optimized */
		      pdr = active->pdr + results[0] - 1;
		      far = sx_get_far_by_id(active, pdr->far_id);
		    }
		}
	      else
		{
		  ip6 = (ip6_header_t *)pl;

		  rte_acl_classify(acl, data, results, 1, 1);
		  clib_warning("Ctx: %p, src: %U, dst %U, r: %d\n",
			       acl,
			       format_ip6_address, &ip6->src_address,
			       format_ip6_address, &ip6->dst_address,
			       results[0]);
		  if (PREDICT_TRUE (results[0] != 0))
		    {
		      vnet_buffer (b)->gtpu.session_index = sidx;
		      vnet_buffer (b)->gtpu.pdr_idx = results[0] - 1;

		      /* TODO: this should be optimized */
		      pdr = active->pdr + results[0] - 1;
		      far = sx_get_far_by_id(active, pdr->far_id);
		    }
		}

	      *teid = save;
	    }

	  if (PREDICT_TRUE (pdr != 0))
	    {
	      /* Outer Header Removal */
	      switch (pdr->outer_header_removal)
		{
		case 0:			/* GTP-U/UDP/IPv4 */
		  if (PREDICT_FALSE ((vnet_buffer (b)->gtpu.flags & BUFFER_HDR_MASK) !=
				     BUFFER_GTP_UDP_IP4))
		    {
		      next = GTPDP_CLASSIFY_NEXT_DROP;
		      // error = GTPDP_CLASSIFY_ERROR_INVALID_OUTER_HEADER;
		      goto trace;
		    }
		  vlib_buffer_advance (b, vnet_buffer (b)->gtpu.data_offset);
		  break;

		case 1:			/* GTP-U/UDP/IPv6 */
		  if (PREDICT_FALSE ((vnet_buffer (b)->gtpu.flags & BUFFER_HDR_MASK) !=
				     BUFFER_GTP_UDP_IP6))
		    {
		      next = GTPDP_CLASSIFY_NEXT_DROP;
		      // error = GTPDP_CLASSIFY_ERROR_INVALID_OUTER_HEADER;
		      goto trace;
		    }
		  vlib_buffer_advance (b, vnet_buffer (b)->gtpu.data_offset);
		  break;

		case 2:			/* UDP/IPv4 */
		  if (PREDICT_FALSE ((vnet_buffer (b)->gtpu.flags & BUFFER_HDR_MASK) !=
				     BUFFER_UDP_IP4))
		    {
		      next = GTPDP_CLASSIFY_NEXT_DROP;
		      // error = GTPDP_CLASSIFY_ERROR_INVALID_OUTER_HEADER;
		      goto trace;
		    }
		  vlib_buffer_advance (b, sizeof(ip4_header_t) + sizeof(udp_header_t));
		  break;

		case 3:			/* UDP/IPv6 */
		  if (PREDICT_FALSE ((vnet_buffer (b)->gtpu.flags & BUFFER_HDR_MASK) !=
				     BUFFER_UDP_IP6))
		    {
		      next = GTPDP_CLASSIFY_NEXT_DROP;
		      // error = GTPDP_CLASSIFY_ERROR_INVALID_OUTER_HEADER;
		      goto trace;
		    }
		  vlib_buffer_advance (b, sizeof(ip6_header_t) + sizeof(udp_header_t));
		  break;
		}

	      ip4 = (ip4_header_t *)pl;
	      switch (far->forward.outer_header_creation)
		{
		case GTP_U_UDP_IPv4:
		  next = GTPDP_CLASSIFY_NEXT_GTPDP4_ENCAP;
		  break;

		case GTP_U_UDP_IPv6:
		  next = GTPDP_CLASSIFY_NEXT_GTPDP6_ENCAP;
		  break;

		case UDP_IPv4:
		  next = GTPDP_CLASSIFY_NEXT_DROP;
		  // error = GTPDP_CLASSIFY_ERROR_NOT_YET;
		  goto trace;

		case UDP_IPv6:
		  next = GTPDP_CLASSIFY_NEXT_DROP;
		  // error = GTPDP_CLASSIFY_ERROR_NOT_YET;
		  goto trace;

		default:
		  ip4 = (ip4_header_t *)vlib_buffer_get_current(b);
		  next = ((ip4->ip_version_and_header_length & 0xF0) == 0x40) ?
		    GTPDP_CLASSIFY_NEXT_IP4_INPUT : GTPDP_CLASSIFY_NEXT_IP6_INPUT;
		  break;
		}

#define IS_DL(_pdr, _far)						\
	  ((_pdr)->pdi.src_intf == SRC_INTF_CORE || (_far)->forward.dst_intf == DST_INTF_ACCESS)
#define IS_UL(_pdr, _far)			\
	  ((_pdr)->pdi.src_intf == SRC_INTF_ACCESS || (_far)->forward.dst_intf == DST_INTF_CORE)

	      process_urrs(vm, active, pdr, b, IS_DL(pdr, far), IS_UL(pdr, far));

#undef IS_DL
#undef IS_UL
	    }

	  len = vlib_buffer_length_in_chain (vm, b);
	  stats_n_packets += 1;
	  stats_n_bytes += len;

	  /* Batch stats increment on the same gtpu tunnel so counter is not
	     incremented per packet. Note stats are still incremented for deleted
	     and admin-down tunnel where packets are dropped. It is not worthwhile
	     to check for this rare case and affect normal path performance. */
	  if (PREDICT_FALSE (sw_if_index != stats_sw_if_index))
	    {
	      stats_n_packets -= 1;
	      stats_n_bytes -= len;
	      if (stats_n_packets)
		vlib_increment_combined_counter
		  (im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_TX,
		   thread_index, stats_sw_if_index,
		   stats_n_packets, stats_n_bytes);
	      stats_n_packets = 1;
	      stats_n_bytes = len;
	      stats_sw_if_index = sw_if_index;
	    }

	trace:
	  if (PREDICT_FALSE(b->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      gtpdp_classify_trace_t *tr =
		vlib_add_trace (vm, node, b, sizeof (*tr));
	      tr->session_index = sidx;
	      tr->cp_f_seid = sess->cp_f_seid;
	      tr->pdr_id = pdr ? pdr->id : ~0;
	      clib_memcpy (tr->packet_data, vlib_buffer_get_current (b),
			   sizeof (tr->packet_data));
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi, next);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return from_frame->n_vectors;
}

static uword
gtpdp_ip4_classify (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * from_frame)
{
	return gtpdp_classify(vm, node, from_frame, /* is_ip4 */ 1);
}

static uword
gtpdp_ip6_classify (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * from_frame)
{
	return gtpdp_classify(vm, node, from_frame, /* is_ip4 */ 0);
}

VLIB_REGISTER_NODE (gtpdp_ip4_classify_node) = {
  .function = gtpdp_ip4_classify,
  .name = "gtpdp-ip4-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_gtpdp_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(gtpdp_classify_error_strings),
  .error_strings = gtpdp_classify_error_strings,
  .n_next_nodes = GTPDP_CLASSIFY_N_NEXT,
  .next_nodes = {
#define _(s,n) [GTPDP_CLASSIFY_NEXT_##s] = n,
    foreach_gtpdp_classify_next
#undef _
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (gtpdp_ip4_classify_node, gtpdp_ip4_classify)

VLIB_REGISTER_NODE (gtpdp_ip6_classify_node) = {
  .function = gtpdp_ip6_classify,
  .name = "gtpdp-ip6-classify",
  .vector_size = sizeof (u32),
  .format_trace = format_gtpdp_classify_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(gtpdp_classify_error_strings),
  .error_strings = gtpdp_classify_error_strings,
  .n_next_nodes = GTPDP_CLASSIFY_N_NEXT,
  .next_nodes = {
#define _(s,n) [GTPDP_CLASSIFY_NEXT_##s] = n,
    foreach_gtpdp_classify_next
#undef _
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (gtpdp_ip6_classify_node, gtpdp_ip6_classify)
