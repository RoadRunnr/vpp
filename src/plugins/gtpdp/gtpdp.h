/*
 * gtpdp.c - 3GPP TS 29.244 GTP-U DP plug-in header file
 *
 * Copyright (c) 2017 Travelping GmbH
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
#ifndef __included_gtpdp_h__
#define __included_gtpdp_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/udp/udp.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

#include "pfcp.h"

/**
 *		Bits
 * Octets	8	7	6	5	4	3	2	1
 * 1		          Version	PT	(*)	E	S	PN
 * 2		Message Type
 * 3		Length (1st Octet)
 * 4		Length (2nd Octet)
 * 5		Tunnel Endpoint Identifier (1st Octet)
 * 6		Tunnel Endpoint Identifier (2nd Octet)
 * 7		Tunnel Endpoint Identifier (3rd Octet)
 * 8		Tunnel Endpoint Identifier (4th Octet)
 * 9		Sequence Number (1st Octet)1) 4)
 * 10		Sequence Number (2nd Octet)1) 4)
 * 11		N-PDU Number2) 4)
 * 12		Next Extension Header Type3) 4)
**/

typedef struct
{
  u8 ver_flags;
  u8 type;
  u16 length;			/* length in octets of the payload */
  u32 teid;
  u16 sequence;
  u8 pdu_number;
  u8 next_ext_type;
} gtpu_header_t;

#define GTPU_VER_MASK (7<<5)
#define GTPU_PT_BIT   (1<<4)
#define GTPU_E_BIT    (1<<2)
#define GTPU_S_BIT    (1<<1)
#define GTPU_PN_BIT   (1<<0)
#define GTPU_E_S_PN_BIT  (7<<0)

#define GTPU_V1_VER   (1<<5)

#define GTPU_PT_GTP    (1<<4)
#define GTPU_TYPE_GTPU  255

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  ip4_header_t ip4;            /* 20 bytes */
  udp_header_t udp;            /* 8 bytes */
  gtpu_header_t gtpu;	       /* 8 bytes */
}) ip4_gtpu_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  ip6_header_t ip6;            /* 40 bytes */
  udp_header_t udp;            /* 8 bytes */
  gtpu_header_t gtpu;     /* 8 bytes */
}) ip6_gtpu_header_t;
/* *INDENT-ON* */

/* Packed so that the mhash key doesn't include uninitialized pad bytes */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip46_address_t addr;
  u32 fib_index;
}) ip46_address_fib_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED
(struct {
  /*
   * Key fields: ip src and gtpu teid on incoming gtpu packet
   * all fields in NET byte order
   */
  union {
    struct {
      u32 dst;
      u32 teid;
    };
    u64 as_u64;
  };
}) gtpu4_tunnel_key_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED
(struct {
  /*
   * Key fields: ip src and gtpu teid on incoming gtpu packet
   * all fields in NET byte order
   */
  ip6_address_t dst;
  u32 teid;
}) gtpu6_tunnel_key_t;
/* *INDENT-ON* */

typedef struct {
  ip46_address_t address;
  u8 mask;
} ipfilter_address_t;

typedef struct {
  u16 min;
  u16 max;
} ipfilter_port_t;

typedef struct {
  enum {
    ACL_PERMIT,
    ACL_DENY
  } action;
  enum {
    ACL_IN,
    ACL_OUT
  } direction;
  u8 proto;
  ipfilter_address_t src_address;
  ipfilter_address_t dst_address;
  ipfilter_port_t src_port;
  ipfilter_port_t dst_port;
} acl_rule_t;

#define ACL_FROM_ANY				\
  (ipfilter_address_t){				\
    .address.as_u64 = {(u64)~0, (u64)~0},	\
    .mask = 0,					\
  }

#define acl_is_from_any(ip)			\
  (((ip)->address.as_u64[0] == (u64)~0) &&	\
   ((ip)->address.as_u64[0] == (u64)~0) &&	\
   ((ip)->mask == 0))

#define ACL_TO_ASSIGNED				\
  (ipfilter_address_t){				\
    .address.as_u64 = {(u64)~0, (u64)~0},	\
    .mask = (u8)~0,				\
  }

#define acl_is_to_assigned(ip)			\
  (((ip)->address.as_u64[0] == (u64)~0) &&	\
   ((ip)->address.as_u64[0] == (u64)~0) &&	\
   ((ip)->mask == (u8)~0))

struct rte_acl_ctx {};

#define INTF_ACCESS	0
#define INTF_CORE	1
#define INTF_SGI_LAN	2
#define INTF_CP		3
#define INTF_LI		4
#define INTF_NUM	(INTF_LI + 1)

/* Packet Detection Information */
typedef struct {
  u8 src_intf;
#define SRC_INTF_ACCESS		0
#define SRC_INTF_CORE		1
#define SRC_INTF_SGI_LAN	2
#define SRC_INTF_CP		3
#define SRC_INTF_NUM		(SRC_INTF_CP + 1)
  u32 src_sw_if_index;
  uword nwi;

  u32 fields;
#define F_PDI_LOCAL_F_TEID    0x0001
#define F_PDI_UE_IP_ADDR      0x0004
#define F_PDI_SDF_FILTER      0x0008
#define F_PDI_APPLICATION_ID  0x0010

  pfcp_f_teid_t teid;
  pfcp_ue_ip_address_t ue_addr;
  acl_rule_t acl;
} gtpdp_pdi_t;

/* Packet Detection Rules */
typedef struct {
  u32 id;
  u16 precedence;

  gtpdp_pdi_t pdi;
  u8 outer_header_removal;
  u16 far_id;
  u16 *urr_ids;
} gtpdp_pdr_t;

/* Forward Action Rules - Forwarding Parameters */
typedef struct {
  int dst_intf;
#define DST_INTF_ACCESS		0
#define DST_INTF_CORE		1
#define DST_INTF_SGI_LAN	2
#define DST_INTF_CP		3
#define DST_INTF_LI		4
  u32 dst_sw_if_index;
  uword nwi;

  u8 outer_header_creation;
#define GTP_U_UDP_IPv4  1
#define GTP_U_UDP_IPv6  2
#define UDP_IPv4        3
#define UDP_IPv6        4

  u32 teid;
  ip46_address_t addr;

  // TODO: UDP encap...
  // u16 port;

  u32 peer_idx;
  u8 * rewrite;
} gtpdp_far_forward_t;

/* Forward Action Rules */
typedef struct {
    u16 id;
    u16 apply_action;
#define FAR_DROP       0x0001
#define FAR_FORWARD    0x0002
#define FAR_BUFFER     0x0004
#define FAR_NOTIFY_CP  0x0008
#define FAR_DUPLICATE  0x0010

    union {
	gtpdp_far_forward_t forward;
	u16 bar_id;
    };
} gtpdp_far_t;

/* Counter */
// TODO: replace with vpp counter
typedef struct {
    u64 bytes;
    u64 pkts;
} gtpdp_cnt_t;

/* Usage Reporting Rules */
typedef struct {
    u16 id;
    u16 methods;
#define SX_URR_TIME   0x0001
#define SX_URR_VOLUME 0x0002
#define SX_URR_EVENT  0x0004

    u16 triggers;
#define SX_URR_PERIODIC  0x0001
#define SX_URR_THRESHOLD 0x0002
#define SX_URR_ENVELOPE  0x0004

    struct {
	struct {
	    u64 ul;
	    u64 dl;
	    u64 total;
	} volume;
    } threshold;

    struct {
	struct {
	    gtpdp_cnt_t ul;
	    gtpdp_cnt_t dl;
	    gtpdp_cnt_t total;
	} volume;
    } measurement;
} gtpdp_urr_t;

typedef struct {
  struct rte_acl_ctx *ip4;
  struct rte_acl_ctx *ip6;
} gtpdp_acl_ctx_t;

typedef struct {
  u64 cp_f_seid;
  uint32_t flags;
#define SX_UPDATING    0x8000

  volatile int active;

  struct rules {
    /* vector of Packet Detection Rules */
    gtpdp_pdr_t *pdr;
    gtpdp_far_t *far;
    gtpdp_urr_t *urr;
    uint32_t flags;
#define SX_SDF_IPV4    0x0001
#define SX_SDF_IPV6    0x0002
    gtpdp_acl_ctx_t sdf[2];
#define UL_SDF 0
#define DL_SDF 1

    ip46_address_fib_t *vrf_ip;
    gtpu4_tunnel_key_t *v4_teid;
    gtpu6_tunnel_key_t *v6_teid;
  } rules[2];
#define SX_ACTIVE  0
#define SX_PENDING 1

  /** FIFO to hold the DL pkts for this session */
  vlib_buffer_t *dl_fifo;

  /* vnet intfc index */
  u32 sw_if_index;
  u32 hw_if_index;

  struct rcu_head rcu_head;
} gtpdp_session_t;

#define foreach_gtpu_input_next        \
_(DROP, "error-drop")                  \
_(IP4_INPUT,  "ip4-input")             \
_(IP6_INPUT, "ip6-input" )

typedef enum
{
#define _(s,n) GTPU_INPUT_NEXT_##s,
  foreach_gtpu_input_next
#undef _
    GTPU_INPUT_N_NEXT,
} gtpu_input_next_t;

typedef enum
{
#define gtpu_error(n,s) GTPU_ERROR_##n,
#include <gtpdp/gtpu_error.def>
#undef gtpu_error
  GTPU_N_ERROR,
} gtpu_input_error_t;

typedef struct {
  uword ref_cnt;

  fib_forward_chain_type_t forw_type;
  u32 encap_index;

  /* The FIB index for src/dst addresses (vrf) */
  u32 encap_fib_index;

  /* FIB DPO for IP forwarding of gtpu encap packet */
  dpo_id_t next_dpo;

  /**
   * Linkage into the FIB object graph
   */
  fib_node_t node;

  /* The FIB entry for sending unicast gtpu encap packets */
  fib_node_index_t fib_entry_index;

  /**
   * The tunnel is a child of the FIB entry for its destination. This is
   * so it receives updates when the forwarding information for that entry
   * changes.
   * The tunnels sibling index on the FIB entry's dependency list.
   */
  u32 sibling_index;
} gtpdp_peer_t;

typedef struct {
  ip46_address_t ip;
  u32 teid;
  u32 mask;
} gtpdp_nwi_ip_res_t;

typedef struct {
  u8 * name;
  u32 vrf;

  u32 intf_sw_if_index[INTF_NUM];
  gtpdp_nwi_ip_res_t * ip_res;
  uword * ip_res_index_by_ip;
} gtpdp_nwi_t;

typedef struct {
  pfcp_node_id_t node_id;
  pfcp_recovery_time_stamp_t recovery_time_stamp;
} gtpdp_node_assoc_t;

typedef struct {
  /* vector of network instances */
  gtpdp_nwi_t *nwis;
  uword *nwi_index_by_name;
  uword *nwi_index_by_sw_if_index;

  /* vector of encap tunnel instances */
  gtpdp_session_t *sessions;

  /* lookup tunnel by key */
  uword *session_by_id;   /* keyed session id */

  /* lookup tunnel by TEID */
  uword *v4_tunnel_by_key;   /* keyed session id */
  uword *v6_tunnel_by_key;   /* keyed session id */

  /* Free vlib hw_if_indices */
  u32 *free_session_hw_if_indices;

  /* Mapping from sw_if_index to tunnel index */
  u32 *session_index_by_sw_if_index;

  /* list of remote GTP-U peer ref count used to stack FIB DPO objects */
  gtpdp_peer_t * peers;
  uword * v4_peer;		/* remote ip4 GTP-U peer keyed on it's ip4 addr */
  uword * v6_peer;		/* remote ip6 GTP-U peer keyed on it's ip6 addr */

  /* vector of associated PFCP nodes */
  gtpdp_node_assoc_t *nodes;
  /* lookup PFCP nodes */
  uword *node_index_by_ip;
  uword *node_index_by_fqdn;

#if 0
  uword *vtep4;
  uword *vtep6;
#endif

  /**
   * Node type for registering to fib changes.
   */
  fib_node_type_t fib_node_type;

  /* API message ID base */
  u16 msg_id_base;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
  ethernet_main_t * ethernet_main;
} gtpdp_main_t;

extern const fib_node_vft_t gtpdp_vft;
extern gtpdp_main_t gtpdp_main;

extern vlib_node_registration_t gtpdp_node;
extern vlib_node_registration_t gtpdp_if_input_node;
extern vlib_node_registration_t gtpu4_input_node;
extern vlib_node_registration_t gtpu6_input_node;
extern vlib_node_registration_t gtpdp4_encap_node;
extern vlib_node_registration_t gtpdp6_encap_node;

int gtpdp_enable_disable (gtpdp_main_t * sm, u32 sw_if_index,
			  int enable_disable);
u8 * format_gtpdp_encap_trace (u8 * s, va_list * args);

#endif /* __included_gtpdp_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
