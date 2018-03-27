/*
 * gtp_up.c - 3GPP TS 29.244 GTP-U UP plug-in header file
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
#ifndef __included_gtp_up_h__
#define __included_gtp_up_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/udp/udp.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_24_8.h>

#include "pfcp.h"

#define BUFFER_HAS_GTP_HDR  (1<<0)
#define BUFFER_HAS_UDP_HDR  (1<<1)
#define BUFFER_HAS_IP4_HDR  (1<<2)
#define BUFFER_HAS_IP6_HDR  (1<<3)
#define BUFFER_HDR_MASK     (BUFFER_HAS_GTP_HDR | BUFFER_HAS_UDP_HDR |	\
			     BUFFER_HAS_IP4_HDR | BUFFER_HAS_IP6_HDR)
#define BUFFER_GTP_UDP_IP4  (BUFFER_HAS_GTP_HDR | BUFFER_HAS_UDP_HDR |	\
			     BUFFER_HAS_IP4_HDR)
#define BUFFER_GTP_UDP_IP6  (BUFFER_HAS_GTP_HDR | BUFFER_HAS_UDP_HDR |	\
			     BUFFER_HAS_IP6_HDR)
#define BUFFER_UDP_IP4      (BUFFER_HAS_UDP_HDR | BUFFER_HAS_IP4_HDR)
#define BUFFER_UDP_IP6      (BUFFER_HAS_UDP_HDR | BUFFER_HAS_IP6_HDR)


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
#define GTPU_TYPE_ERROR_IND    26
#define GTPU_TYPE_END_MARKER  254
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
  u32 teid;
  ip46_address_t addr;
  u16 port;
} gtp_error_ind_t;

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
} gtp_up_pdi_t;

/* Packet Detection Rules */
typedef struct {
  u32 id;
  u16 precedence;

  gtp_up_pdi_t pdi;
  u8 outer_header_removal;
  u16 far_id;
  u16 *urr_ids;
} gtp_up_pdr_t;

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
} gtp_up_far_forward_t;

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
	gtp_up_far_forward_t forward;
	u16 bar_id;
    };
} gtp_up_far_t;

/* Counter */

enum {
  URR_COUNTER_UL = 0,
  URR_COUNTER_DL,
  URR_COUNTER_TOTAL,
  URR_COUNTER_NUM,
};

// TODO: replace with vpp counter
typedef struct {
    u64 bytes;
    u64 pkts;
} gtp_up_cnt_t;

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
      u64 volume[URR_COUNTER_NUM];
    } threshold;

    struct {
      vlib_combined_counter_main_t volume;
    } measurement;
} gtp_up_urr_t;

typedef struct {
  struct rte_acl_ctx *ip4;
  struct rte_acl_ctx *ip6;
} gtp_up_acl_ctx_t;

typedef struct {
  /* Sx UDP socket handle */
  u64 session_handle;

  u64 cp_f_seid;
  uint32_t flags;
#define SX_UPDATING    0x8000

  volatile int active;

  struct rules {
    /* vector of Packet Detection Rules */
    gtp_up_pdr_t *pdr;
    gtp_up_far_t *far;
    gtp_up_urr_t *urr;
    uint32_t flags;
#define SX_SDF_IPV4    0x0001
#define SX_SDF_IPV6    0x0002
    gtp_up_acl_ctx_t sdf[2];
#define UL_SDF 0
#define DL_SDF 1

    ip46_address_fib_t *vrf_ip;
    gtpu4_tunnel_key_t *v4_teid;
    gtpu6_tunnel_key_t *v6_teid;

    uword *v4_wildcard_teid;
    uword *v6_wildcard_teid;

    u16 * send_end_marker;
  } rules[2];
#define SX_ACTIVE  0
#define SX_PENDING 1

  /** FIFO to hold the DL pkts for this session */
  vlib_buffer_t *dl_fifo;

  /* vnet intfc index */
  u32 sw_if_index;
  u32 hw_if_index;

  struct rcu_head rcu_head;
} gtp_up_session_t;


typedef enum
{
#define gtpu_error(n,s) GTPU_ERROR_##n,
#include <gtp-up/gtpu_error.def>
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
} gtp_up_peer_t;

typedef struct {
  ip46_address_t ip;
  u32 teid;
  u32 mask;
} gtp_up_nwi_ip_res_t;

typedef struct {
  u8 * name;
  u32 vrf;

  u32 intf_sw_if_index[INTF_NUM];
  gtp_up_nwi_ip_res_t * ip_res;
  uword * ip_res_index_by_ip;
} gtp_up_nwi_t;

typedef struct {
  pfcp_node_id_t node_id;
  pfcp_recovery_time_stamp_t recovery_time_stamp;
} gtp_up_node_assoc_t;

#define GTP_UP_MAPPING_BUCKETS      1024
#define GTP_UP_MAPPING_MEMORY_SIZE  64 << 20

typedef struct {
  /* vector of network instances */
  gtp_up_nwi_t *nwis;
  uword *nwi_index_by_name;
  uword *nwi_index_by_sw_if_index;
  u8 *intf_type_by_sw_if_index;

  /* vector of encap tunnel instances */
  gtp_up_session_t *sessions;

  /* lookup tunnel by key */
  uword *session_by_id;   /* keyed session id */

  /* lookup tunnel by TEID */
  clib_bihash_8_8_t v4_tunnel_by_key;    /* keyed session id */
  clib_bihash_24_8_t v6_tunnel_by_key;   /* keyed session id */

  /* Free vlib hw_if_indices */
  u32 *free_session_hw_if_indices;

  /* Mapping from sw_if_index to tunnel index */
  u32 *session_index_by_sw_if_index;

  /* list of remote GTP-U peer ref count used to stack FIB DPO objects */
  gtp_up_peer_t * peers;
  uword * peer_index_by_ip;	/* remote GTP-U peer keyed on it's ip addr and vrf */

  /* vector of associated PFCP nodes */
  gtp_up_node_assoc_t *nodes;
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
} gtp_up_main_t;

extern const fib_node_vft_t gtp_up_vft;
extern gtp_up_main_t gtp_up_main;

extern vlib_node_registration_t gtp_up_node;
extern vlib_node_registration_t gtp_up_if_input_node;
extern vlib_node_registration_t gtpu4_input_node;
extern vlib_node_registration_t gtpu6_input_node;
extern vlib_node_registration_t gtp_up4_encap_node;
extern vlib_node_registration_t gtp_up6_encap_node;

int gtp_up_enable_disable (gtp_up_main_t * sm, u32 sw_if_index,
			  int enable_disable);
u8 * format_gtp_up_encap_trace (u8 * s, va_list * args);
void gtpu_send_end_marker(gtp_up_far_forward_t * forward);

#endif /* __included_gtp_up_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */