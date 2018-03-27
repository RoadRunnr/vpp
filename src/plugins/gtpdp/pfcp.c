/*
 * Copyright(c) 2018 Travelping GmbH.
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

#include <assert.h>

#define _LGPL_SOURCE            /* LGPL v3.0 is compatible with Apache 2.0 */
#include <urcu-qsbr.h>          /* QSBR RCU flavor */

#define _BSD_SOURCE
#include <endian.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <vppinfra/vec.h>
#include <vppinfra/format.h>

#include "pfcp.h"

#define DEBUG_PFCP

#ifdef DEBUG_PFCP
#define pfcp_debug clib_warning
#else
#define pfcp_debug(...)				\
  do { } while (0)
#endif
#define pfcp_warning clib_warning

/*************************************************************************/

u8 *
format_network_instance(u8 * s, va_list * args)
{
  u8 * label = va_arg (*args, u8 *);
  u8 i = 0;

  if (!label)
    return format (s, "invalid");

  if (*label > 64)
    {
      vec_append(s, label);
      return s;
    }

  while (i < vec_len(label))
    {
      if (i != 0)
	vec_add1(s, '.');
      vec_add(s, label + i + 1, label[i]);
      i += label[i] + 1;
    }

  return s;
}

/*************************************************************************/

static const char *msg_desc[] =
  {
    [PFCP_HEARTBEAT_REQUEST] = "Heartbeat Request",
    [PFCP_HEARTBEAT_RESPONSE] = "Heartbeat Response",
    [PFCP_PFD_MANAGEMENT_REQUEST] = "PFD Management Request",
    [PFCP_PFD_MANAGEMENT_RESPONSE] = "PFD Management Response",
    [PFCP_ASSOCIATION_SETUP_REQUEST] = "Association Setup Request",
    [PFCP_ASSOCIATION_SETUP_RESPONSE] = "Association Setup Response",
    [PFCP_ASSOCIATION_UPDATE_REQUEST] = "Association Update Request",
    [PFCP_ASSOCIATION_UPDATE_RESPONSE] = "Association Update Response",
    [PFCP_ASSOCIATION_RELEASE_REQUEST] = "Association Release Request",
    [PFCP_ASSOCIATION_RELEASE_RESPONSE] = "Association Release Response",
    [PFCP_VERSION_NOT_SUPPORTED_RESPONSE] = "Version Not Supported Response",
    [PFCP_NODE_REPORT_REQUEST] = "Node Report Request",
    [PFCP_NODE_REPORT_RESPONSE] = "Node Report Response",
    [PFCP_SESSION_SET_DELETION_REQUEST] = "Session Set Deletion Request",
    [PFCP_SESSION_SET_DELETION_RESPONSE] = "Session Set Deletion Response",
    [PFCP_SESSION_ESTABLISHMENT_REQUEST] = "Session Establishment Request",
    [PFCP_SESSION_ESTABLISHMENT_RESPONSE] = "Session Establishment Response",
    [PFCP_SESSION_MODIFICATION_REQUEST] = "Session Modification Request",
    [PFCP_SESSION_MODIFICATION_RESPONSE] = "Session Modification Response",
    [PFCP_SESSION_DELETION_REQUEST] = "Session Deletion Request",
    [PFCP_SESSION_DELETION_RESPONSE] = "Session Deletion Response",
    [PFCP_SESSION_REPORT_REQUEST] = "Session Report Request",
    [PFCP_SESSION_REPORT_RESPONSE] = "Session Report Response",
  };

static const char *ie_desc[] =
  {
    [PFCP_IE_CREATE_PDR] = "Create PDR",
    [PFCP_IE_PDI] = "PDI",
    [PFCP_IE_CREATE_FAR] = "Create FAR",
    [PFCP_IE_FORWARDING_PARAMETERS] = "Forwarding Parameters",
    [PFCP_IE_DUPLICATING_PARAMETERS] = "Duplicating Parameters",
    [PFCP_IE_CREATE_URR] = "Create URR",
    [PFCP_IE_CREATE_QER] = "Create QER",
    [PFCP_IE_CREATED_PDR] = "Created PDR",
    [PFCP_IE_UPDATE_PDR] = "Update PDR",
    [PFCP_IE_UPDATE_FAR] = "Update FAR",
    [PFCP_IE_UPDATE_FORWARDING_PARAMETERS] = "Update Forwarding Parameters",
    [PFCP_IE_UPDATE_BAR_RESPONSE] = "Update BAR Response",
    [PFCP_IE_UPDATE_URR] = "Update URR",
    [PFCP_IE_UPDATE_QER] = "Update QER",
    [PFCP_IE_REMOVE_PDR] = "Remove PDR",
    [PFCP_IE_REMOVE_FAR] = "Remove FAR",
    [PFCP_IE_REMOVE_URR] = "Remove URR",
    [PFCP_IE_REMOVE_QER] = "Remove QER",
    [PFCP_IE_CAUSE] = "Cause",
    [PFCP_IE_SOURCE_INTERFACE] = "Source Interface",
    [PFCP_IE_F_TEID] = "F-TEID",
    [PFCP_IE_NETWORK_INSTANCE] = "Network Instance",
    [PFCP_IE_SDF_FILTER] = "SDF Filter",
    [PFCP_IE_APPLICATION_ID] = "Application ID",
    [PFCP_IE_GATE_STATUS] = "Gate Status",
    [PFCP_IE_MBR] = "MBR",
    [PFCP_IE_GBR] = "GBR",
    [PFCP_IE_QER_CORRELATION_ID] = "QER Correlation ID",
    [PFCP_IE_PRECEDENCE] = "Precedence",
    [PFCP_IE_TRANSPORT_LEVEL_MARKING] = "Transport Level Marking",
    [PFCP_IE_VOLUME_THRESHOLD] = "Volume Threshold",
    [PFCP_IE_TIME_THRESHOLD] = "Time Threshold",
    [PFCP_IE_MONITORING_TIME] = "Monitoring Time",
    [PFCP_IE_SUBSEQUENT_VOLUME_THRESHOLD] = "Subsequent Volume Threshold",
    [PFCP_IE_SUBSEQUENT_TIME_THRESHOLD] = "Subsequent Time Threshold",
    [PFCP_IE_INACTIVITY_DETECTION_TIME] = "Inactivity Detection Time",
    [PFCP_IE_REPORTING_TRIGGERS] = "Reporting Triggers",
    [PFCP_IE_REDIRECT_INFORMATION] = "Redirect Information",
    [PFCP_IE_REPORT_TYPE] = "Report Type",
    [PFCP_IE_OFFENDING_IE] = "Offending IE",
    [PFCP_IE_FORWARDING_POLICY] = "Forwarding Policy",
    [PFCP_IE_DESTINATION_INTERFACE] = "Destination Interface",
    [PFCP_IE_UP_FUNCTION_FEATURES] = "UP Function Features",
    [PFCP_IE_APPLY_ACTION] = "Apply Action",
    [PFCP_IE_DOWNLINK_DATA_SERVICE_INFORMATION] = "Downlink Data Service Information",
    [PFCP_IE_DOWNLINK_DATA_NOTIFICATION_DELAY] = "Downlink Data Notification Delay",
    [PFCP_IE_DL_BUFFERING_DURATION] = "DL Buffering Duration",
    [PFCP_IE_DL_BUFFERING_SUGGESTED_PACKET_COUNT] = "DL Buffering Suggested Packet Count",
    [PFCP_IE_SXSMREQ_FLAGS] = "SxSMReq-Flags",
    [PFCP_IE_SXSRRSP_FLAGS] = "SxSRRsp-Flags",
    [PFCP_IE_LOAD_CONTROL_INFORMATION] = "Load Control Information",
    [PFCP_IE_SEQUENCE_NUMBER] = "Sequence Number",
    [PFCP_IE_METRIC] = "Metric",
    [PFCP_IE_OVERLOAD_CONTROL_INFORMATION] = "Overload Control Information",
    [PFCP_IE_TIMER] = "Timer",
    [PFCP_IE_F_SEID] = "F-SEID",
    [PFCP_IE_APPLICATION_ID_PFDS] = "Application ID PFDs",
    [PFCP_IE_PFD] = "PFD",
    [PFCP_IE_NODE_ID] = "Node ID",
    [PFCP_IE_PFD_CONTENTS] = "PFD contents",
    [PFCP_IE_MEASUREMENT_METHOD] = "Measurement Method",
    [PFCP_IE_USAGE_REPORT_TRIGGER] = "Usage Report Trigger",
    [PFCP_IE_MEASUREMENT_PERIOD] = "Measurement Period",
    [PFCP_IE_FQ_CSID] = "FQ-CSID",
    [PFCP_IE_VOLUME_MEASUREMENT] = "Volume Measurement",
    [PFCP_IE_DURATION_MEASUREMENT] = "Duration Measurement",
    [PFCP_IE_APPLICATION_DETECTION_INFORMATION] = "Application Detection Information",
    [PFCP_IE_TIME_OF_FIRST_PACKET] = "Time of First Packet",
    [PFCP_IE_TIME_OF_LAST_PACKET] = "Time of Last Packet",
    [PFCP_IE_QUOTA_HOLDING_TIME] = "Quota Holding Time",
    [PFCP_IE_DROPPED_DL_TRAFFIC_THRESHOLD] = "Dropped DL Traffic Threshold",
    [PFCP_IE_VOLUME_QUOTA] = "Volume Quota",
    [PFCP_IE_TIME_QUOTA] = "Time Quota",
    [PFCP_IE_START_TIME] = "Start Time",
    [PFCP_IE_END_TIME] = "End Time",
    [PFCP_IE_QUERY_URR] = "Query URR",
    [PFCP_IE_USAGE_REPORT_SMR] = "Usage Report SMR",
    [PFCP_IE_USAGE_REPORT_SDR] = "Usage Report SDR",
    [PFCP_IE_USAGE_REPORT_SRR] = "Usage Report SRR",
    [PFCP_IE_URR_ID] = "URR ID",
    [PFCP_IE_LINKED_URR_ID] = "Linked URR ID",
    [PFCP_IE_DOWNLINK_DATA_REPORT] = "Downlink Data Report",
    [PFCP_IE_OUTER_HEADER_CREATION] = "Outer Header Creation",
    [PFCP_IE_CREATE_BAR] = "Create BAR",
    [PFCP_IE_UPDATE_BAR_REQUEST] = "Update BAR Request",
    [PFCP_IE_REMOVE_BAR] = "Remove BAR",
    [PFCP_IE_BAR_ID] = "BAR ID",
    [PFCP_IE_CP_FUNCTION_FEATURES] = "CP Function Features",
    [PFCP_IE_USAGE_INFORMATION] = "Usage Information",
    [PFCP_IE_APPLICATION_INSTANCE_ID] = "Application Instance ID",
    [PFCP_IE_FLOW_INFORMATION] = "Flow Information",
    [PFCP_IE_UE_IP_ADDRESS] = "UE IP Address",
    [PFCP_IE_PACKET_RATE] = "Packet Rate",
    [PFCP_IE_OUTER_HEADER_REMOVAL] = "Outer Header Removal",
    [PFCP_IE_RECOVERY_TIME_STAMP] = "Recovery Time Stamp",
    [PFCP_IE_DL_FLOW_LEVEL_MARKING] = "DL Flow Level Marking",
    [PFCP_IE_HEADER_ENRICHMENT] = "Header Enrichment",
    [PFCP_IE_ERROR_INDICATION_REPORT] = "Error Indication Report",
    [PFCP_IE_MEASUREMENT_INFORMATION] = "Measurement Information",
    [PFCP_IE_NODE_REPORT_TYPE] = "Node Report Type",
    [PFCP_IE_USER_PLANE_PATH_FAILURE_REPORT] = "User Plane Path Failure Report",
    [PFCP_IE_REMOTE_GTP_U_PEER] = "Remote GTP-U Peer",
    [PFCP_IE_UR_SEQN] = "UR-SEQN",
    [PFCP_IE_UPDATE_DUPLICATING_PARAMETERS] = "Update Duplicating Parameters",
    [PFCP_IE_ACTIVATE_PREDEFINED_RULES] = "Activate Predefined Rules",
    [PFCP_IE_DEACTIVATE_PREDEFINED_RULES] = "Deactivate Predefined Rules",
    [PFCP_IE_FAR_ID] = "FAR ID",
    [PFCP_IE_QER_ID] = "QER ID",
    [PFCP_IE_OCI_FLAGS] = "OCI Flags",
    [PFCP_IE_SX_ASSOCIATION_RELEASE_REQUEST] = "Sx Association Release Request",
    [PFCP_IE_GRACEFUL_RELEASE_PERIOD] = "Graceful Release Period",
    [PFCP_IE_PDN_TYPE] = "PDN Type",
    [PFCP_IE_FAILED_RULE_ID] = "Failed Rule ID",
    [PFCP_IE_TIME_QUOTA_MECHANISM] = "Time Quota Mechanism",
    [PFCP_IE_USER_PLANE_IP_RESOURCE_INFORMATION] = "User Plane IP Resource Information",
  };

u8 *
format_pfcp_msg_hdr(u8 * s, va_list * args)
{
  pfcp_header_t *pfcp = va_arg (*args, pfcp_header_t *);
  u8 type = pfcp->type;

  if (type < ARRAY_LEN(msg_desc) && msg_desc[type])
    return format(s, "PFCP: V:%d,S:%d,MP:%d, %s (%d), Length: %d.",
		  pfcp->version, pfcp->s_flag, pfcp->mp_flag,
		  msg_desc[type], type, clib_net_to_host_u16 (pfcp->length));
  else
    return format(s, "PFCP: V:%d,S:%d,MP:%d, %d, Length: %d.",
		  pfcp->version, pfcp->s_flag, pfcp->mp_flag,
		  type, clib_net_to_host_u16 (pfcp->length));
}

u8 *
format_pfcp_ie(u8 * s, va_list * args)
{
  pfcp_ie_t *ie = va_arg (*args, pfcp_ie_t *);
  u16 type = clib_net_to_host_u16 (ie->type);

  if (type < ARRAY_LEN(ie_desc) && ie_desc[type])
    return format(s, "IE: %s (%d), Length: %d.",
		  ie_desc[type], type, clib_net_to_host_u16 (ie->length));
  else
    return format(s, "IE: %d, Length: %d.", type, clib_net_to_host_u16 (ie->length));
}

/*************************************************************************/

/* message construction helpers */

#define set_msg_hdr_version(V,VER) ((pfcp_header_t *)(V))->version = (VER)
#define set_msg_hdr_type(V,TYPE) ((pfcp_header_t *)(V))->type = (TYPE)
#define set_msg_hdr_seq(V,S)						\
  do {									\
    ((pfcp_header_t *)(V))->msg_hdr.sequence[0] = (S >> 16) &0xff;	\
    ((pfcp_header_t *)(V))->msg_hdr.sequence[1] = (S >> 8) &0xff;	\
    ((pfcp_header_t *)(V))->msg_hdr.sequence[2] = S &0xff;		\
  } while (0)
#define copy_msg_hdr_seq(V,S)						\
  clib_memcpy(((pfcp_header_t *)(V))->msg_hdr.sequence, (S)->msg_hdr.sequence, \
	      sizeof(S->msg_hdr.sequence))
#define set_msg_hdr_length(V,LEN) ((pfcp_header_t *)(V))->length =  htons((LEN))

#define put_msg_response(V,REQ,TYPE,P)		\
  do {						\
    set_msg_hdr_version((V), 1);		\
    set_msg_hdr_type((V), (TYPE));		\
    copy_msg_hdr_seq((V), (REQ));		\
    (P) = NODE_MSG_HDR_LEN;			\
  } while (0)

#define set_ie_hdr_type(V,TYPE,P)  ((pfcp_ie_t *)&(V)[(P)])->type = htons((TYPE))
#define set_ie_hdr_length(V,LEN,P) ((pfcp_ie_t *)&(V)[(P)])->length = htons((LEN))
#define put_ie_hdr(V,TYPE,LEN,P)		\
  do {						\
    set_ie_hdr_type(V,TYPE,P);			\
    set_ie_hdr_length(V,LEN,P);			\
    (P) += sizeof(pfcp_ie_t);			\
  } while (0)
#define finalize_ie(V,HDR,P) set_ie_hdr_length((V), (P) - (HDR) - sizeof(pfcp_ie_t), (HDR))

#define set_ie_vendor_hdr_type(V,TYPE,VEND,P)			\
  ((pfcp_ievendor__t *)&(V)[(P)])->type = htons((TYPE))
#define set_ie_vendor_hdr_length(V,LEN,P)			\
  ((pfcp_ie_vendor_t *)&(V)[(P)])->length = htons((LEN))
#define set_ie_vendor_hdr_vendor(V,VEND,P)			\
  ((pfcp_ie_vendor_t *)&(V)[(P)])->vendor = htons((VEND))
#define put_ie_vendor_hdr(V,TYPE,VEND,LEN,P)			\
  do {								\
    set_ie_vendor_hdr_type((V),(TYPE) & 0x8000,(P));		\
    set_ie_vendor_hdr_length((V),(LEN),(P));			\
    set_ie_vendor_hdr_vendor((V),(VEND),(P));			\
    (P) += sizeof(pfcp_ie_vendor_t);				\
  } while (0)

#define put_u8(V,I)				\
  do {						\
    *((u8 *)&(V)[_vec_len((V))]) = (I);		\
    _vec_len((V)) += sizeof(u8);		\
  } while (0)

#define get_u8(V)				\
  ({u8 *_V = (V);				\
    (V)++;					\
    *_V; })

#define put_u16(V,I)				\
  do {						\
    *((u16 *)&(V)[_vec_len((V))]) = htons((I));	\
    _vec_len((V)) += sizeof(u16);		\
  } while (0)

#define get_u16(V)				\
  ({u16 *_V = (u16 *)(V);			\
    (V) += sizeof(u16);				\
    ntohs(*_V); })

#define put_u24(V,I)					\
  do {							\
    (V)[_vec_len((V))] = (I) >> 16;			\
    (V)[_vec_len((V)) + 1] = ((I) >> 8) & 0xff;		\
    (V)[_vec_len((V)) + 2] = (I) & 0xff;		\
    _vec_len((V)) += 3;					\
  } while (0)

#define get_u24(V)						\
  ({u32 _V = ((V)[0] << 16) | ((V)[1] << 8) | ((V)[2]);		\
    (V) += 3;							\
    _V; })

#define put_u32(V,I)				\
  do {						\
    *((u32 *)&(V)[_vec_len((V))]) = htonl((I));	\
    _vec_len((V)) += sizeof(u32);		\
  } while (0)

#define get_u32(V)				\
  ({u32 *_V = (u32 *)(V);			\
    (V) += sizeof(u32);				\
    ntohl(*_V); })

#define put_u64(V,I)					\
  do {							\
    *((u64 *)&(V)[_vec_len((V))]) = htobe64((I));	\
    _vec_len((V)) += sizeof(u64);			\
  } while (0)

#define get_u64(V)				\
  ({u64 *_V = (u64 *)(V);			\
    (V) += sizeof(u64);				\
    be64toh(*_V); })

#define get_ip4(IP,V)				\
  do {						\
    (IP).as_u32 = *(u32 *)(V);			\
    (V) += 4;					\
  } while (0)

#define put_ip4(V,IP)				\
  do {						\
    u8 *_t = vec_end((V));			\
    *(u32 *)_t = (IP).as_u32;			\
    _vec_len((V)) += 4;				\
  } while (0)

#define get_ip6(IP,V)				\
  do {						\
    (IP).as_u64[0] = ((u64 *)(V))[0];		\
    (IP).as_u64[1] = ((u64 *)(V))[1];		\
    (V) += 16;					\
  } while (0)

#define put_ip6(V,IP)				\
  do {						\
    u8 *_t = vec_end((V));			\
    ((u64 *)_t)[0] = (IP).as_u64[0];		\
    ((u64 *)_t)[1] = (IP).as_u64[1];		\
    _vec_len((V)) += 16;			\
} while (0)

#define put_ip46_ip4(V,IP)			\
  put_ip4(V, (IP).ip4)

#define get_ip46_ip4(IP,V)				\
  do {							\
    ip46_address_set_ip4(&(IP), (ip4_address_t *)(V));	\
    (V) += 4;						\
  } while (0)

#define put_ip46_ip6(V,IP)			\
  put_ip6(V, (IP).ip6)

#define get_ip46_ip6(IP,V)			\
  get_ip6((IP).ip6, (V))

#define finalize_msg(V,P)			\
  do {						\
    set_msg_hdr_length(V,(P) - 4);		\
    _vec_len((V)) = (P);			\
  } while (0)

/* generic IEs */

static int decode_volume_ie(u8 *data, u16 length, pfcp_volume_ie_t *v)
{
  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->fields = get_u8(data) & 0x07;

  if (length < 1 + __builtin_popcount(v->fields) * sizeof(u64))
    return PFCP_CAUSE_INVALID_LENGTH;

  if (v->fields & 0x01)                            /* Total Volume */
    v->total = get_u64(data);
  if (v->fields & 0x02)                            /* Uplink Volume */
    v->ul = get_u64(data);
  if (v->fields & 0x04)                            /* Downlink Volume */
    v->dl = get_u64(data);

  return 0;
}

static int encode_volume_ie(pfcp_volume_ie_t *v, u8 **vec)
{
  put_u8(*vec, v->fields);

  if (v->fields & 0x01)                            /* Total Volume */
    put_u64(*vec, v->total);
  if (v->fields & 0x02)                            /* Uplink Volume */
    put_u64(*vec, v->ul);
  if (v->fields & 0x04)                            /* Downlink Volume */
    put_u64(*vec, v->dl);

  return 0;
}

static int decode_time_stamp_ie(u8 *data, u16 length, u32 *v)
{
  if (length != 4)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = ntohl(*(u32 *)data);
  if (*v & 0x80000000)
    *v -= 2208988800;  /* use base: 1-Jan-1900 @ 00:00:00 UTC */
  else
    *v += 2085978496;  /* use base: 7-Feb-2036 @ 06:28:16 UTC */

  return 0;
}

static int encode_time_stamp_ie(u32 *v, u8 **vec)
{
  if (*v >= 2085978496)
    put_u32(*vec, *v - 2085978496);
  else
    put_u32(*vec, *v + 2208988800);

  return 0;
}

/* Information Elements */

static int decode_cause(u8 *data, u16 length, void *p)
{
  pfcp_cause_t *v = p;

  if (length != 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u8(data);

  pfcp_debug ("PFCP: Cause: %d.", *v);
  return 0;
}

static int encode_cause(void *p, u8 **vec)
{
  pfcp_cause_t *v = p;

  pfcp_debug ("PFCP: Cause: %d.", *v);

  put_u8(*vec, *v);
  return 0;
}

static int decode_source_interface(u8 *data, u16 length, void *p)
{
  pfcp_source_interface_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u8(data) & 0x0f;
  if (*v >= 4)
    return PFCP_CAUSE_REQUEST_REJECTED;

  pfcp_debug ("PFCP: Source Interface: %d.", *v);
  return 0;
}

static int encode_source_interface(void *p, u8 **vec)
{
  pfcp_source_interface_t *v = p;

  pfcp_debug ("PFCP: Source Interface: %d.", *v);

  put_u8(*vec, *v & 0x0f);
  return 0;
}

static void debug_f_teid(pfcp_f_teid_t *v)
{
  if ((v->flags & 0xf) == F_TEID_V4)
      pfcp_debug ("PFCP: F-TEID: %d,IPv4:%U.",
		    v->teid, format_ip4_address, &v->ip4);
  else if ((v->flags & 0xf) == F_TEID_V6)
      pfcp_debug ("PFCP: F-TEID: %d,IPv6:%U.",
		    v->teid, format_ip6_address, &v->ip6);
  else if ((v->flags & 0xf) == (F_TEID_V4 | F_TEID_V6))
      pfcp_debug ("PFCP: F-TEID: %d,IPv4:%U,IPv6:%U.",
		    v->teid, format_ip4_address, &v->ip4,
		    format_ip6_address, &v->ip6);
  else if ((v->flags & 0xf) == F_TEID_CH)
    pfcp_debug ("PFCP: F-TEID: %d,CH:1.", v->teid);
  else if ((v->flags & 0xf) == (F_TEID_CH | F_TEID_CHID))
    pfcp_debug ("PFCP: F-TEID: %d,CH:1,CHID:%d.", v->teid, v->choose_id);
  else
    pfcp_debug ("PFCP: F-TEID with invalid flags: %02x.", v->flags);
}

static int decode_f_teid(u8 *data, u16 length, void *p)
{
  pfcp_f_teid_t *v = p;

  if (length < 5)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->flags = get_u8(data) & 0x0f;
  v->teid = get_u32(data);
  length -= 5;

  pfcp_debug ("PFCP: F-TEID, Len: %d, TEID: %d, Flags: %02x.", length, v->teid, v->flags);

  if (v->flags & F_TEID_CH)
    {
      if (v->flags & (F_TEID_V4 | F_TEID_V6))
	{
	  pfcp_warning ("PFCP: F-TEID with invalid flags (CH and v4/v6): %02x.", v->flags);
	  return -1;
	}
    }
  else
    {
      if (v->flags & F_TEID_CHID)
	{
	  pfcp_warning ("PFCP: F-TEID with invalid flags (CHID without CH): %02x.", v->flags);
	  return -1;
	}
      if (!(v->flags & (F_TEID_V4 | F_TEID_V6)))
	{
	  pfcp_warning ("PFCP: F-TEID without v4/v6 address: %02x.", v->flags);
	  return -1;
	}
    }

  if (v->flags & F_TEID_V4)
    {
      if (length < 4)
	return PFCP_CAUSE_INVALID_LENGTH;

      get_ip4(v->ip4, data);
      length -= 4;
    }

  if (v->flags & F_TEID_V6)
    {
      if (length < 16)
	return PFCP_CAUSE_INVALID_LENGTH;

      get_ip6(v->ip6, data);
      length -= 16;
    }

  if (v->flags & F_TEID_CHID)
    {
      if (length < 1)
	return PFCP_CAUSE_INVALID_LENGTH;

      v->choose_id = get_u8(data);
    }

  debug_f_teid(v);
  return 0;
}

static int encode_f_teid(void *p, u8 **vec)
{
  pfcp_f_teid_t *v = p;

  debug_f_teid(v);

  put_u8(*vec, v->flags);
  put_u32(*vec, v->teid);
  if (v->flags & F_TEID_V4)
    put_ip4(*vec, v->ip4);
  if (v->flags & F_TEID_V6)
    put_ip6(*vec, v->ip6);
  if (v->flags & F_TEID_CHID)
    put_u8(*vec, v->choose_id);
  return 0;
}

static int decode_network_instance(u8 *data, u16 length, void *p)
{
  pfcp_network_instance_t *v = p;

  vec_reset_length(*v);
  vec_add(*v, data, length);

  pfcp_debug ("PFCP: Network Instance: '%U'", format_network_instance, *v);
  return 0;
}

static int encode_network_instance(void *p, u8 **vec)
{
  pfcp_network_instance_t *v = p;

  pfcp_debug ("PFCP: Network Instance: '%U'", format_network_instance, *v);

  vec_append(*vec, p);

  return 0;
}

static void free_network_instance(void *p)
{
  pfcp_network_instance_t *v = p;

  vec_free(*v);
}

static void debug_sdf_filter(pfcp_sdf_filter_t *v)
{
  return;
}

static int decode_sdf_filter(u8 *data, u16 length, void *p)
{
  pfcp_sdf_filter_t *v = p;

  if (length < 2)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->flags = get_u8(data) & 0x0f;
  data++; /* spare */
  length -= 2;

  if (v->flags & F_SDF_FD)
    {
      u16 flow_len;

      if (length < 2)
	return PFCP_CAUSE_INVALID_LENGTH;

      flow_len = get_u16(data);
      length -= 2;

      if (length < flow_len)
	return PFCP_CAUSE_INVALID_LENGTH;

      vec_reset_length(v->flow);
      vec_add(v->flow, data, flow_len);
      length -= flow_len;
    }

  if (v->flags & F_SDF_TTC)
    {
      if (length < 2)
	return PFCP_CAUSE_INVALID_LENGTH;

      v->tos_traffic_class = get_u16(data);
      length -= 2;
    }

  if (v->flags & F_SDF_SPI)
    {
      if (length < 4)
	return PFCP_CAUSE_INVALID_LENGTH;

      v->spi = get_u32(data);
      length -= 4;
    }

  if (v->flags & F_SDF_FL)
    {
      if (length < 3)
	return PFCP_CAUSE_INVALID_LENGTH;

      v->flow_label = get_u24(data);
      length -= 3;
    }

  debug_sdf_filter(v);
  return 0;
}

static int encode_sdf_filter(void *p, u8 **vec)
{
  pfcp_sdf_filter_t *v = p;

  debug_sdf_filter(v);

  put_u8(*vec, v->flags & 0x0f);
  if (v->flags & F_SDF_FD)
    {
      put_u16(*vec, _vec_len(v->flow));
      vec_append(*vec, v->flow);
    }
  if (v->flags & F_SDF_TTC)
    put_u16(*vec, v->tos_traffic_class);
  if (v->flags & F_SDF_SPI)
    put_u32(*vec, v->spi);
  if (v->flags & F_SDF_FL)
    put_u24(*vec, v->flow_label);

  return 0;
}

static void free_sdf_filter(void *p)
{
  pfcp_sdf_filter_t *v = p;

  vec_free(v->flow);
}

static int decode_application_id(u8 *data, u16 length, void *p)
{
  pfcp_application_id_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_application_id");
  return 0;
}

static int encode_application_id(void *p, u8 **vec)
{
  pfcp_application_id_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_application_id");
  return 0;
}

static int decode_gate_status(u8 *data, u16 length, void *p)
{
  pfcp_gate_status_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_gate_status");
  return 0;
}

static int encode_gate_status(void *p, u8 **vec)
{
  pfcp_gate_status_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_gate_status");
  return 0;
}

static int decode_mbr(u8 *data, u16 length, void *p)
{
  pfcp_mbr_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_mbr");
  return 0;
}

static int encode_mbr(void *p, u8 **vec)
{
  pfcp_mbr_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_mbr");
  return 0;
}

static int decode_gbr(u8 *data, u16 length, void *p)
{
  pfcp_gbr_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_gbr");
  return 0;
}

static int encode_gbr(void *p, u8 **vec)
{
  pfcp_gbr_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_gbr");
  return 0;
}

static int decode_qer_correlation_id(u8 *data, u16 length, void *p)
{
  pfcp_qer_correlation_id_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_qer_correlation_id");
  return 0;
}

static int encode_qer_correlation_id(void *p, u8 **vec)
{
  pfcp_qer_correlation_id_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_qer_correlation_id");
  return 0;
}

static int decode_precedence(u8 *data, u16 length, void *p)
{
  pfcp_precedence_t *v = p;

  if (length < 4)
	      return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u32(data);

  pfcp_debug ("PFCP: Precedence: %d.", *v);
  return 0;
}

static int encode_precedence(void *p, u8 **vec)
{
  pfcp_precedence_t *v = p;

  pfcp_debug ("PFCP: Measurement Method: %d.", *v);

  put_u32(*vec, *v);
  return 0;
}

static int decode_transport_level_marking(u8 *data, u16 length, void *p)
{
  pfcp_transport_level_marking_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_transport_level_marking");
  return 0;
}

static int encode_transport_level_marking(void *p, u8 **vec)
{
  pfcp_transport_level_marking_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_transport_level_marking");
  return 0;
}

static int decode_volume_threshold(u8 *data, u16 length, void *p)
{
  pfcp_volume_threshold_t *v = p;
  int r;

  if ((r = decode_volume_ie(data, length, v)) == 0)
    pfcp_debug ("PFCP: Volume Threshold: T:%d,U:%d,D:%d", v->total, v->ul, v->dl);

  return r;
}

static int encode_volume_threshold(void *p, u8 **vec)
{
  pfcp_volume_threshold_t *v = p;

  pfcp_debug ("PFCP: Volume Threshold: T:%d,U:%d,D:%d", v->total, v->ul, v->dl);
  return encode_volume_ie(v, vec);
}

static int decode_time_threshold(u8 *data, u16 length, void *p)
{
  pfcp_time_threshold_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_time_threshold");
  return 0;
}

static int encode_time_threshold(void *p, u8 **vec)
{
  pfcp_time_threshold_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_time_threshold");
  return 0;
}

static int decode_monitoring_time(u8 *data, u16 length, void *p)
{
  pfcp_monitoring_time_t *v = p;
  int r;

  if ((r = decode_time_stamp_ie(data, length, v)) == 0)
    pfcp_debug ("PFCP: Monitoring Time: %d.", *v);

  return r;
}

static int encode_monitoring_time(void *p, u8 **vec)
{
  pfcp_monitoring_time_t *v = p;

  pfcp_debug ("PFCP: Monitoring Time: %d.", *v);

  return encode_time_stamp_ie(v, vec);
}

static int decode_subsequent_volume_threshold(u8 *data, u16 length, void *p)
{
  pfcp_subsequent_volume_threshold_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_subsequent_volume_threshold");
  return 0;
}

static int encode_subsequent_volume_threshold(void *p, u8 **vec)
{
  pfcp_subsequent_volume_threshold_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_subsequent_volume_threshold");
  return 0;
}

static int decode_subsequent_time_threshold(u8 *data, u16 length, void *p)
{
  pfcp_subsequent_time_threshold_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_subsequent_time_threshold");
  return 0;
}

static int encode_subsequent_time_threshold(void *p, u8 **vec)
{
  pfcp_subsequent_time_threshold_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_subsequent_time_threshold");
  return 0;
}

static int decode_inactivity_detection_time(u8 *data, u16 length, void *p)
{
  pfcp_inactivity_detection_time_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_inactivity_detection_time");
  return 0;
}

static int encode_inactivity_detection_time(void *p, u8 **vec)
{
  pfcp_inactivity_detection_time_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_inactivity_detection_time");
  return 0;
}

static int decode_reporting_triggers(u8 *data, u16 length, void *p)
{
  pfcp_reporting_triggers_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_reporting_triggers");
  return 0;
}

static int encode_reporting_triggers(void *p, u8 **vec)
{
  pfcp_reporting_triggers_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_reporting_triggers");
  return 0;
}

static int decode_redirect_information(u8 *data, u16 length, void *p)
{
  pfcp_redirect_information_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_redirect_information");
  return 0;
}

static int encode_redirect_information(void *p, u8 **vec)
{
  pfcp_redirect_information_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_redirect_information");
  return 0;
}

static int decode_report_type(u8 *data, u16 length, void *p)
{
  pfcp_report_type_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u8(data) & 0x07;

  pfcp_debug ("PFCP: Report Type: ERIR:%d,USAR:%d,DLDR:%d",
	      !!(*v & REPORT_TYPE_ERIR),
	      !!(*v & REPORT_TYPE_USAR),
	      !!(*v & REPORT_TYPE_DLDR));
  return 0;
}

static int encode_report_type(void *p, u8 **vec)
{
  pfcp_report_type_t *v = p;

  pfcp_debug ("PFCP: Report Type: ERIR:%d,USAR:%d,DLDR:%d",
	      !!(*v & REPORT_TYPE_ERIR),
	      !!(*v & REPORT_TYPE_USAR),
	      !!(*v & REPORT_TYPE_DLDR));

  put_u8(*vec, *v);
  return 0;
}

static int decode_offending_ie(u8 *data, u16 length, void *p)
{
  pfcp_offending_ie_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_offending_ie");
  return 0;
}

static int encode_offending_ie(void *p, u8 **vec)
{
  pfcp_offending_ie_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_offending_ie");
  return 0;
}

static int decode_forwarding_policy(u8 *data, u16 length, void *p)
{
  pfcp_forwarding_policy_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_forwarding_policy");
  return 0;
}

static int encode_forwarding_policy(void *p, u8 **vec)
{
  pfcp_forwarding_policy_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_forwarding_policy");
  return 0;
}

static int decode_destination_interface(u8 *data, u16 length, void *p)
{
  pfcp_destination_interface_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u8(data) & 0x0f;
  if (*v >= 5)
    return PFCP_CAUSE_REQUEST_REJECTED;

  pfcp_debug ("PFCP: Destination Interface: %d.", *v);
  return 0;
}

static int encode_destination_interface(void *p, u8 **vec)
{
  pfcp_destination_interface_t *v = p;

  pfcp_debug ("PFCP: Destination Interface: %d.", *v);

  put_u8(*vec, *v);
  return 0;
}

static int decode_up_function_features(u8 *data, u16 length, void *p)
{
  pfcp_up_function_features_t *v = p;

  if (length < 2)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u16(data);

  pfcp_warning ("PFCP: UP Function Features: BUCP:%d,DDND:%d,DLBD:%d,"
		"TRST:%d,FTUP:%d,PFDM:%d,HEEU:%d,TREU:%d,EMPU:%d",
		!!(*v & F_UPFF_BUCP), !!(*v & F_UPFF_DDND),
		!!(*v & F_UPFF_DLBD), !!(*v & F_UPFF_TRST),
		!!(*v & F_UPFF_FTUP), !!(*v & F_UPFF_PFDM),
		!!(*v & F_UPFF_HEEU), !!(*v & F_UPFF_TREU),
		!!(*v & F_UPFF_EMPU));
  return 0;
}

static int encode_up_function_features(void *p, u8 **vec)
{
  pfcp_up_function_features_t *v = p;

  pfcp_warning ("PFCP: UP Function Features: BUCP:%d,DDND:%d,DLBD:%d,"
		"TRST:%d,FTUP:%d,PFDM:%d,HEEU:%d,TREU:%d,EMPU:%d",
		!!(*v & F_UPFF_BUCP), !!(*v & F_UPFF_DDND),
		!!(*v & F_UPFF_DLBD), !!(*v & F_UPFF_TRST),
		!!(*v & F_UPFF_FTUP), !!(*v & F_UPFF_PFDM),
		!!(*v & F_UPFF_HEEU), !!(*v & F_UPFF_TREU),
		!!(*v & F_UPFF_EMPU));

  put_u16(*vec, *v);
  return 0;
}

static int decode_apply_action(u8 *data, u16 length, void *p)
{
  pfcp_apply_action_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u8(data) & 0x1f;

  pfcp_debug ("PFCP: Apply Action: DUPL:%d,NOCP:%d,BUFF:%d,FORW:%d,DROP:%d",
		!!(*v & 0x10), !!(*v & 0x08), !!(*v & 0x04), !!(*v & 0x02), !!(*v & 0x01));
  return 0;
}

static int encode_apply_action(void *p, u8 **vec)
{
  pfcp_apply_action_t *v = p;

  pfcp_debug ("PFCP: Apply Action: DUPL:%d,NOCP:%d,BUFF:%d,FORW:%d,DROP:%d",
		!!(*v & 0x10), !!(*v & 0x08), !!(*v & 0x04), !!(*v & 0x02), !!(*v & 0x01));

  put_u8(*vec, *v);
  return 0;
}

static int decode_downlink_data_service_information(u8 *data, u16 length, void *p)
{
  pfcp_downlink_data_service_information_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_downlink_data_service_information");
  return 0;
}

static int encode_downlink_data_service_information(void *p, u8 **vec)
{
  pfcp_downlink_data_service_information_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_downlink_data_service_information");
  return 0;
}

static int decode_downlink_data_notification_delay(u8 *data, u16 length, void *p)
{
  pfcp_downlink_data_notification_delay_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_downlink_data_notification_delay");
  return 0;
}

static int encode_downlink_data_notification_delay(void *p, u8 **vec)
{
  pfcp_downlink_data_notification_delay_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_downlink_data_notification_delay");
  return 0;
}

static int decode_dl_buffering_duration(u8 *data, u16 length, void *p)
{
  pfcp_dl_buffering_duration_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_dl_buffering_duration");
  return 0;
}

static int encode_dl_buffering_duration(void *p, u8 **vec)
{
  pfcp_dl_buffering_duration_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_dl_buffering_duration");
  return 0;
}

static int decode_dl_buffering_suggested_packet_count(u8 *data, u16 length, void *p)
{
  pfcp_dl_buffering_suggested_packet_count_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_dl_buffering_suggested_packet_count");
  return 0;
}

static int encode_dl_buffering_suggested_packet_count(void *p, u8 **vec)
{
  pfcp_dl_buffering_suggested_packet_count_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_dl_buffering_suggested_packet_count");
  return 0;
}

static int decode_sxsmreq_flags(u8 *data, u16 length, void *p)
{
  pfcp_sxsmreq_flags_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u8(data);

  pfcp_warning ("PFCP: SxSMReq Flags: DROBU:%d,SNDEM:%d,QUARR:%d",
		!!(*v & SXSMREQ_DROBU), !!(*v & SXSMREQ_SNDEM),
		!!(*v & SXSMREQ_QAURR));
  return 0;
}

static int encode_sxsmreq_flags(void *p, u8 **vec)
{
  pfcp_sxsmreq_flags_t *v = p;

  pfcp_warning ("PFCP: SxSMReq Flags: DROBU:%d,SNDEM:%d,QUARR:%d",
		!!(*v & SXSMREQ_DROBU), !!(*v & SXSMREQ_SNDEM),
		!!(*v & SXSMREQ_QAURR));

  put_u8(*vec, *v);
  return 0;
}

static int decode_sxsrrsp_flags(u8 *data, u16 length, void *p)
{
  pfcp_sxsrrsp_flags_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u8(data);

  pfcp_warning ("PFCP: SxSRRsp Flags: DROBU:%d", !!(*v & SXSRRSP_DROBU));
  return 0;
}

static int encode_sxsrrsp_flags(void *p, u8 **vec)
{
  pfcp_sxsrrsp_flags_t *v = p;

  pfcp_warning ("PFCP: SxSRRsp Flags: DROBU:%d", !!(*v & SXSRRSP_DROBU));

  put_u8(*vec, *v);
  return 0;
}

static int decode_sequence_number(u8 *data, u16 length, void *p)
{
  pfcp_sequence_number_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_sequence_number");
  return 0;
}

static int encode_sequence_number(void *p, u8 **vec)
{
  pfcp_sequence_number_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_sequence_number");
  return 0;
}

static int decode_metric(u8 *data, u16 length, void *p)
{
  pfcp_metric_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_metric");
  return 0;
}

static int encode_metric(void *p, u8 **vec)
{
  pfcp_metric_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_metric");
  return 0;
}

static int decode_timer(u8 *data, u16 length, void *p)
{
  pfcp_timer_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_timer");
  return 0;
}

static int encode_timer(void *p, u8 **vec)
{
  pfcp_timer_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_timer");
  return 0;
}

static int decode_pdr_id(u8 *data, u16 length, void *p)
{
  pfcp_pdr_id_t *v = p;

  if (length < 2)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u16(data);

  pfcp_debug ("PFCP: PDR Id: %d.", *v);
  return 0;
}

static int encode_pdr_id(void *p, u8 **vec)
{
  pfcp_pdr_id_t *v = p;

  pfcp_debug ("PFCP: PDR Id: %d.", *v);

  put_u16(*vec, *v);
  return 0;
}

static void debug_f_seid(pfcp_f_seid_t *v)
{
  switch (v->flags & (IE_F_SEID_IP_ADDRESS_V4 | IE_F_SEID_IP_ADDRESS_V6))
    {
    case IE_F_SEID_IP_ADDRESS_V4:
      pfcp_debug ("PFCP: F-SEID 0x%016" PRIx64 " (%" PRIu64 "),IPv4:%U.",
		  v->seid, v->seid, format_ip4_address, &v->ip4);
      break;

    case IE_F_SEID_IP_ADDRESS_V6:
      pfcp_debug ("PFCP: F-SEID 0x%016" PRIx64 " (%" PRIu64 "),IPv6:%U.",
		  v->seid, v->seid, format_ip4_address, &v->ip6);
      break;

    case (IE_F_SEID_IP_ADDRESS_V4 | IE_F_SEID_IP_ADDRESS_V6):
      pfcp_debug ("PFCP: F-SEID 0x%016" PRIx64 " (%" PRIu64 "),IPv4:%U,IPv6:%U.",
		  v->seid, v->seid,
		  format_ip4_address, &v->ip4,
		  format_ip4_address, &v->ip6);
      break;
    }
}

static int decode_f_seid(u8 *data, u16 length, void *p)
{
  pfcp_f_seid_t *v = p;

  if (length < 9)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->flags = get_u8(data) & 0x03;
  if (v->flags == 0)
    {
      pfcp_warning ("PFCP: F-SEID with unsupported flags: %02x.", v->flags);
      return -1;
    }

  v->seid = get_u64(data);

  if (v->flags & IE_F_SEID_IP_ADDRESS_V4)
    {
      if (length < 4)
	return PFCP_CAUSE_INVALID_LENGTH;

      get_ip4(v->ip4, data);
      length -= 4;
    }

  if (v->flags & IE_F_SEID_IP_ADDRESS_V6)
    {
      if (length < 16)
	return PFCP_CAUSE_INVALID_LENGTH;

      get_ip6(v->ip6, data);
    }

  debug_f_seid (v);
  return 0;
}

static int encode_f_seid(void *p, u8 **vec)
{
  pfcp_f_seid_t *v __attribute__ ((unused)) = p;

  debug_f_seid (v);

  put_u8(*vec, v->flags);
  put_u64(*vec, v->seid);

  if (v->flags & IE_F_SEID_IP_ADDRESS_V4)
    put_ip4(*vec, v->ip4);

  if (v->flags & IE_F_SEID_IP_ADDRESS_V6)
    put_ip6(*vec, v->ip6);

  return 0;
}

u8 *
format_node_id(u8 * s, va_list * args)
{
  pfcp_node_id_t *n = va_arg (*args, pfcp_node_id_t *);

  switch (n->type)
    {
    case NID_IPv4:
    case NID_IPv6:
      s = format(s, "%U", format_ip46_address, &n->ip, IP46_TYPE_ANY);
      break;

    case NID_FQDN:
      s = format(s, "%U", format_network_instance, &n->fqdn);
      break;
    }
  return s;
}

static int decode_node_id(u8 *data, u16 length, void *p)
{
  pfcp_node_id_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->type = get_u8(data) & 0x0f;
  length--;

  switch (v->type)
    {
    case NID_IPv4:
      if (length < 4)
	return PFCP_CAUSE_INVALID_LENGTH;
      get_ip46_ip4(v->ip, data);
      break;

    case NID_IPv6:
      if (length < 16)
	return PFCP_CAUSE_INVALID_LENGTH;
      get_ip46_ip6(v->ip, data);
      break;

    case NID_FQDN:
      vec_reset_length(v->fqdn);
      vec_add(v->fqdn, data, length);
      break;

    default:
      return PFCP_CAUSE_REQUEST_REJECTED;
    }

  pfcp_debug ("PFCP: Node Id: %U.", format_node_id, v);
  return 0;
}

static int encode_node_id(void *p, u8 **vec)
{
  pfcp_node_id_t *v = p;

  pfcp_debug ("PFCP: Node Id: %U.", format_node_id, v);

  put_u8(*vec, v->type);

  switch (v->type)
    {
    case NID_IPv4:
      put_ip46_ip4(*vec, v->ip);
      break;

    case NID_IPv6:
      put_ip46_ip6(*vec, v->ip);
      break;

    case NID_FQDN:
      vec_append(*vec, v->fqdn);
      break;
    }

  return 0;
}

static void free_node_id(void *p)
{
  pfcp_node_id_t *v = p;

  vec_free(v->fqdn);
}

static int decode_pfd_contents(u8 *data, u16 length, void *p)
{
  pfcp_pfd_contents_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_pfd_contents");
  return 0;
}

static int encode_pfd_contents(void *p, u8 **vec)
{
  pfcp_pfd_contents_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_pfd_contents");
  return 0;
}

static int decode_measurement_method(u8 *data, u16 length, void *p)
{
  pfcp_measurement_method_t *v = p;

  if (length < 1)
	      return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u8(data);

  pfcp_debug ("PFCP: Measurement Method: %d.", *v);
  return 0;
}

static int encode_measurement_method(void *p, u8 **vec)
{
  pfcp_measurement_method_t *v = p;

  pfcp_debug ("PFCP: Measurement Method: %d.", *v);

  put_u8(*vec, *v & 0x07);
  return 0;
}

static int decode_usage_report_trigger(u8 *data, u16 length, void *p)
{
  pfcp_usage_report_trigger_t *v = p;

  if (length < 2)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = (data[1] << 8) & data[0];

  pfcp_debug ("PFCP: Usage Report Trigger: "
		"PERIO:%d,VOLTH:%d,TIMTH:%d,QUHTI:%d,"
		"START:%d,STOPT:%d,DROTH:%d,IMMER:%d",
		!!(*v & USAGE_REPORT_TRIGGER_PERIODIC_REPORTING),
		!!(*v & USAGE_REPORT_TRIGGER_VOLUME_THRESHOLD),
		!!(*v & USAGE_REPORT_TRIGGER_TIME_THRESHOLD),
		!!(*v & USAGE_REPORT_TRIGGER_QUOTA_HOLDING_TIME),
		!!(*v & USAGE_REPORT_TRIGGER_START_OF_TRAFFIC),
		!!(*v & USAGE_REPORT_TRIGGER_STOP_OF_TRAFFIC),
		!!(*v & USAGE_REPORT_TRIGGER_DROPPED_DL_TRAFFIC_THRESHOLD),
		!!(*v & USAGE_REPORT_TRIGGER_IMMEDIATE_REPORT));
  pfcp_debug ("PFCP: Usage Report Trigger: "
		"VOLQU:%d,TIMQU:%d,LIUSA:%d,TERMR:%d,"
		"MONIT:%d,ENVCL:%d",
		!!(*v & USAGE_REPORT_TRIGGER_VOLUME_QUOTA),
		!!(*v & USAGE_REPORT_TRIGGER_TIME_QUOTA),
		!!(*v & USAGE_REPORT_TRIGGER_LINKED_USAGE_REPORTING),
		!!(*v & USAGE_REPORT_TRIGGER_TERMINATION_REPORT),
		!!(*v & USAGE_REPORT_TRIGGER_MONITORING_TIME),
		!!(*v & USAGE_REPORT_TRIGGER_ENVELOPE_CLOSURE));
  return 0;
}

static int encode_usage_report_trigger(void *p, u8 **vec)
{
  pfcp_usage_report_trigger_t *v = p;

  pfcp_debug ("PFCP: Usage_Report_Trigger: "
		"PERIO:%d,VOLTH:%d,TIMTH:%d,QUHTI:%d,"
		"START:%d,STOPT:%d,DROTH:%d,IMMER:%d",
		!!(*v & USAGE_REPORT_TRIGGER_PERIODIC_REPORTING),
		!!(*v & USAGE_REPORT_TRIGGER_VOLUME_THRESHOLD),
		!!(*v & USAGE_REPORT_TRIGGER_TIME_THRESHOLD),
		!!(*v & USAGE_REPORT_TRIGGER_QUOTA_HOLDING_TIME),
		!!(*v & USAGE_REPORT_TRIGGER_START_OF_TRAFFIC),
		!!(*v & USAGE_REPORT_TRIGGER_STOP_OF_TRAFFIC),
		!!(*v & USAGE_REPORT_TRIGGER_DROPPED_DL_TRAFFIC_THRESHOLD),
		!!(*v & USAGE_REPORT_TRIGGER_IMMEDIATE_REPORT));
  pfcp_debug ("PFCP: Usage_Report_Trigger: "
		"VOLQU:%d,TIMQU:%d,LIUSA:%d,TERMR:%d,"
		"MONIT:%d,ENVCL:%d",
		!!(*v & USAGE_REPORT_TRIGGER_VOLUME_QUOTA),
		!!(*v & USAGE_REPORT_TRIGGER_TIME_QUOTA),
		!!(*v & USAGE_REPORT_TRIGGER_LINKED_USAGE_REPORTING),
		!!(*v & USAGE_REPORT_TRIGGER_TERMINATION_REPORT),
		!!(*v & USAGE_REPORT_TRIGGER_MONITORING_TIME),
		!!(*v & USAGE_REPORT_TRIGGER_ENVELOPE_CLOSURE));

  put_u8(*vec, *v & 0xff);
  put_u8(*vec, (*v >> 8) & 0xff);
  return 0;
}

static int decode_measurement_period(u8 *data, u16 length, void *p)
{
  pfcp_measurement_period_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_measurement_period");
  return 0;
}

static int encode_measurement_period(void *p, u8 **vec)
{
  pfcp_measurement_period_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_measurement_period");
  return 0;
}

static int decode_fq_csid(u8 *data, u16 length, void *p)
{
  pfcp_fq_csid_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_fq_csid");
  return 0;
}

static int encode_fq_csid(void *p, u8 **vec)
{
  pfcp_fq_csid_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_fq_csid");
  return 0;
}

static int decode_volume_measurement(u8 *data, u16 length, void *p)
{
  pfcp_volume_measurement_t *v = p;
  int r;

  if ((r = decode_volume_ie(data, length, v)) == 0)
    pfcp_debug ("PFCP: Volume Measurement: T:%d,U:%d,D:%d", v->total, v->ul, v->dl);

  return r;
}

static int encode_volume_measurement(void *p, u8 **vec)
{
  pfcp_volume_measurement_t *v = p;

  pfcp_debug ("PFCP: Volume Measurement: T:%d,U:%d,D:%d", v->total, v->ul, v->dl);
  return encode_volume_ie(v, vec);
}

static int decode_duration_measurement(u8 *data, u16 length, void *p)
{
  pfcp_duration_measurement_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_duration_measurement");
  return 0;
}

static int encode_duration_measurement(void *p, u8 **vec)
{
  pfcp_duration_measurement_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_duration_measurement");
  return 0;
}

static int decode_time_of_first_packet(u8 *data, u16 length, void *p)
{
  pfcp_time_of_first_packet_t *v = p;
  int r;

  if ((r = decode_time_stamp_ie(data, length, v)) == 0)
    pfcp_debug ("PFCP: Time of First Packet: %d.", *v);

  return r;
}

static int encode_time_of_first_packet(void *p, u8 **vec)
{
  pfcp_time_of_first_packet_t *v = p;

  pfcp_debug ("PFCP: Time of First Packet: %d.", *v);

  return encode_time_stamp_ie(v, vec);
}

static int decode_time_of_last_packet(u8 *data, u16 length, void *p)
{
  pfcp_time_of_last_packet_t *v = p;
  int r;

  if ((r = decode_time_stamp_ie(data, length, v)) == 0)
    pfcp_debug ("PFCP: Time of Last Packet: %d.", *v);

  return r;
}

static int encode_time_of_last_packet(void *p, u8 **vec)
{
  pfcp_time_of_last_packet_t *v = p;

  pfcp_debug ("PFCP: Time of Last Packet: %d.", *v);

  return encode_time_stamp_ie(v, vec);
}

static int decode_quota_holding_time(u8 *data, u16 length, void *p)
{
  pfcp_quota_holding_time_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_quota_holding_time");
  return 0;
}

static int encode_quota_holding_time(void *p, u8 **vec)
{
  pfcp_quota_holding_time_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_quota_holding_time");
  return 0;
}

static int decode_dropped_dl_traffic_threshold(u8 *data, u16 length, void *p)
{
  pfcp_dropped_dl_traffic_threshold_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_dropped_dl_traffic_threshold");
  return 0;
}

static int encode_dropped_dl_traffic_threshold(void *p, u8 **vec)
{
  pfcp_dropped_dl_traffic_threshold_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_dropped_dl_traffic_threshold");
  return 0;
}

static int decode_volume_quota(u8 *data, u16 length, void *p)
{
  pfcp_volume_quota_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_volume_quota");
  return 0;
}

static int encode_volume_quota(void *p, u8 **vec)
{
  pfcp_volume_quota_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_volume_quota");
  return 0;
}

static int decode_time_quota(u8 *data, u16 length, void *p)
{
  pfcp_time_quota_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_time_quota");
  return 0;
}

static int encode_time_quota(void *p, u8 **vec)
{
  pfcp_time_quota_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_time_quota");
  return 0;
}

static int decode_start_time(u8 *data, u16 length, void *p)
{
  pfcp_start_time_t *v = p;
  int r;

  if ((r = decode_time_stamp_ie(data, length, v)) == 0)
    pfcp_debug ("PFCP: Start Time: %d.", *v);

  return r;
}

static int encode_start_time(void *p, u8 **vec)
{
  pfcp_start_time_t *v = p;

  pfcp_debug ("PFCP: Start Time: %d.", *v);

  return encode_time_stamp_ie(v, vec);
}

static int decode_end_time(u8 *data, u16 length, void *p)
{
  pfcp_end_time_t *v = p;
  int r;

  if ((r = decode_time_stamp_ie(data, length, v)) == 0)
    pfcp_debug ("PFCP: End Time: %d.", *v);

  return r;
}

static int encode_end_time(void *p, u8 **vec)
{
  pfcp_end_time_t *v = p;

  pfcp_debug ("PFCP: End Time: %d.", *v);

  return encode_time_stamp_ie(v, vec);
}

static int decode_urr_id(u8 *data, u16 length, void *p)
{
  pfcp_urr_id_t *v = p;

  if (length < 4)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u32(data);

  pfcp_debug ("PFCP: URR Id: %d (%p).", *v, v);
  return 0;
}

static int encode_urr_id(void *p, u8 **vec)
{
  pfcp_urr_id_t *v = p;

  pfcp_debug ("PFCP: URR Id: %d.", *v);

  put_u32(*vec, *v);
  return 0;
}

static int decode_linked_urr_id(u8 *data, u16 length, void *p)
{
  pfcp_linked_urr_id_t *v = p;

  if (length < 4)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u32(data);

  pfcp_debug ("PFCP: LINKED_URR Id: %d.", *v);
  return 0;
}

static int encode_linked_urr_id(void *p, u8 **vec)
{
  pfcp_linked_urr_id_t *v = p;

  pfcp_debug ("PFCP: Linked URR Id: %d.", *v);

  put_u32(*vec, *v);
  return 0;
}

static int decode_outer_header_creation(u8 *data, u16 length, void *p)
{
  pfcp_outer_header_creation_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->type = get_u8(data);
  length--;
  if (v->type >= 4)
    return PFCP_CAUSE_REQUEST_REJECTED;

  switch (v->type)
    {
    case 0:                               /* GTP-U/UDP/IPv4 */
      if (length < 8)
	return PFCP_CAUSE_INVALID_LENGTH;
      v->teid = get_u32(data);
      get_ip46_ip4(v->addr, data);

      pfcp_debug ("PFCP: Outer Header Creation GTP-U/UDP/IPv4, TEID:%08x,IP:%U.",
		    v->teid, format_ip46_address, &v->addr, IP46_TYPE_ANY);
      break;

    case 1:                               /* GTP-U/UDP/IPv6 */
      if (length < 20)
	return PFCP_CAUSE_INVALID_LENGTH;
      v->teid = get_u32(data);
      get_ip46_ip6(v->addr, data);

      pfcp_debug ("PFCP: Outer Header Creation GTP-U/UDP/IPv6, TEID:%08x,IP:%U.",
		    v->teid, format_ip46_address, &v->addr, IP46_TYPE_ANY);
      break;

    case 2:                               /* UDP/IPv4 */
      if (length < 6)
	return PFCP_CAUSE_INVALID_LENGTH;
      get_ip46_ip4(v->addr, data);
      v->port = get_u16(data);

      pfcp_debug ("PFCP: Outer Header Creation UDP/IPv4, IP:%U,Port:%d.",
		    format_ip46_address, &v->addr, IP46_TYPE_ANY, v->port);
      break;

    case 3:                               /* UDP/IPv6 */
      if (length < 18)
	return PFCP_CAUSE_INVALID_LENGTH;
      get_ip46_ip6(v->addr, data);
      v->port = get_u16(data);

      pfcp_debug ("PFCP: Outer Header Creation UDP/IPv6, IP:%U,Port:%d.",
		    format_ip46_address, &v->addr, IP46_TYPE_ANY, v->port);
      break;
    }

  return 0;
}

static int encode_outer_header_creation(void *p, u8 **vec)
{
  pfcp_outer_header_creation_t *v = p;

  put_u8(*vec, v->type);

  switch (v->type)
    {
    case 0:                               /* GTP-U/UDP/IPv4 */
      pfcp_debug ("PFCP: Outer Header Creation GTP-U/UDP/IPv4, TEID:%08x,IP:%U.",
		    v->teid, format_ip46_address, &v->addr, IP46_TYPE_ANY);

      put_u32(*vec, v->teid);
      put_ip46_ip4(*vec, v->addr);
      break;

    case 1:                               /* GTP-U/UDP/IPv6 */
      pfcp_debug ("PFCP: Outer Header Creation GTP-U/UDP/IPv6, TEID:%08x,IP:%U.",
		    v->teid, format_ip46_address, &v->addr, IP46_TYPE_ANY);

      put_u32(*vec, v->teid);
      put_ip46_ip6(*vec, v->addr);
      break;

    case 2:                               /* UDP/IPv4 */
      pfcp_debug ("PFCP: Outer Header Creation UDP/IPv4, IP:%U,Port:%d.",
		    format_ip46_address, &v->addr, IP46_TYPE_ANY, v->port);

      put_ip46_ip4(*vec, v->addr);
      put_u16(*vec, v->port);
      break;

    case 3:                               /* UDP/IPv6 */
      pfcp_debug ("PFCP: Outer Header Creation UDP/IPv6, IP:%U,Port:%d.",
		    format_ip46_address, &v->addr, IP46_TYPE_ANY, v->port);

      put_ip46_ip6(*vec, v->addr);
      put_u16(*vec, v->port);
      break;
    }

  return 0;
}

static int decode_bar_id(u8 *data, u16 length, void *p)
{
  pfcp_bar_id_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u8(data);

  pfcp_debug ("PFCP: BAR Id: %d.", *v);
  return 0;
}

static int encode_bar_id(void *p, u8 **vec)
{
  pfcp_bar_id_t *v = p;

  pfcp_debug ("PFCP: BAR Id: %d.", *v);

  put_u8(*vec, *v);
  return 0;
}

static int decode_cp_function_features(u8 *data, u16 length, void *p)
{
  pfcp_cp_function_features_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_cp_function_features");
  return 0;
}

static int encode_cp_function_features(void *p, u8 **vec)
{
  pfcp_cp_function_features_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_cp_function_features");
  return 0;
}

static int decode_usage_information(u8 *data, u16 length, void *p)
{
  pfcp_usage_information_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_usage_information");
  return 0;
}

static int encode_usage_information(void *p, u8 **vec)
{
  pfcp_usage_information_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_usage_information");
  return 0;
}

static int decode_application_instance_id(u8 *data, u16 length, void *p)
{
  pfcp_application_instance_id_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_application_instance_id");
  return 0;
}

static int encode_application_instance_id(void *p, u8 **vec)
{
  pfcp_application_instance_id_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_application_instance_id");
  return 0;
}

static int decode_flow_information(u8 *data, u16 length, void *p)
{
  pfcp_flow_information_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_flow_information");
  return 0;
}

static int encode_flow_information(void *p, u8 **vec)
{
  pfcp_flow_information_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_flow_information");
  return 0;
}

static void debug_ue_ip_address(pfcp_ue_ip_address_t *v)
{
  switch (v->flags & (IE_UE_IP_ADDRESS_V4 | IE_UE_IP_ADDRESS_V6))
    {
    case IE_UE_IP_ADDRESS_V4:
      pfcp_debug ("PFCP: UE IP Addr, S/D:%d,IPv4:%U.",
		    !!(v->flags & IE_UE_IP_ADDRESS_SD),
		    format_ip4_address, &v->ip4);
      break;

    case IE_UE_IP_ADDRESS_V6:
      pfcp_debug ("PFCP: UE IP Addr, S/D:%d,IPv6:%U.",
		    !!(v->flags & IE_UE_IP_ADDRESS_SD),
		    format_ip4_address, &v->ip6);
      break;

    case (IE_UE_IP_ADDRESS_V4 | IE_UE_IP_ADDRESS_V6):
      pfcp_debug ("PFCP: UE IP Addr, S/D:%d,IPv4:%U,IPv6:%U.",
		    !!(v->flags & IE_UE_IP_ADDRESS_SD),
		    format_ip4_address, &v->ip4,
		    format_ip4_address, &v->ip6);
      break;

    default:
      pfcp_debug ("PFCP: UE IP Addr, S/D:%d.", !!(v->flags & IE_UE_IP_ADDRESS_SD));
      break;
    }
}

static int decode_ue_ip_address(u8 *data, u16 length, void *p)
{
  pfcp_ue_ip_address_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->flags = get_u8(data);
  length--;

  if (v->flags & IE_UE_IP_ADDRESS_V4)
    {
      if (length < 4)
	return PFCP_CAUSE_INVALID_LENGTH;

      get_ip4(v->ip4, data);
      length -= 4;
    }

  if (v->flags & IE_UE_IP_ADDRESS_V6)
    {
      if (length < 16)
	return PFCP_CAUSE_INVALID_LENGTH;

      get_ip6(v->ip6, data);
    }

  debug_ue_ip_address(v);
  return 0;
}

static int encode_ue_ip_address(void *p, u8 **vec)
{
  pfcp_ue_ip_address_t *v = p;

  debug_ue_ip_address(v);

  put_u8(*vec, v->flags);
  if (v->flags & IE_UE_IP_ADDRESS_V4)
    put_ip4(*vec, v->ip4);
  if (v->flags & IE_UE_IP_ADDRESS_V6)
    put_ip6(*vec, v->ip6);

  return 0;
}

static int decode_packet_rate(u8 *data, u16 length, void *p)
{
  pfcp_packet_rate_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_packet_rate");
  return 0;
}

static int encode_packet_rate(void *p, u8 **vec)
{
  pfcp_packet_rate_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_packet_rate");
  return 0;
}

static int decode_outer_header_removal(u8 *data, u16 length, void *p)
{
  pfcp_outer_header_removal_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u8(data);

  pfcp_debug ("PFCP: Outer Header Removal: %d.", *v);
  return 0;
}

static int encode_outer_header_removal(void *p, u8 **vec)
{
  pfcp_outer_header_removal_t *v = p;

  pfcp_debug ("PFCP: Outer Header Removal: %d.", *v);

  put_u8(*vec, *v);
  return 0;
}

static int decode_recovery_time_stamp(u8 *data, u16 length, void *p)
{
  pfcp_recovery_time_stamp_t *v = p;
  int r;

  if ((r = decode_time_stamp_ie(data, length, v)) == 0)
    pfcp_debug ("PFCP: Recovery Time Stamp: %d.", *v);

  return r;
}

static int encode_recovery_time_stamp(void *p, u8 **vec)
{
  pfcp_recovery_time_stamp_t *v = p;

  pfcp_debug ("PFCP: Recovery Time Stamp: %d.", *v);

  return encode_time_stamp_ie(v, vec);
}

static int decode_dl_flow_level_marking(u8 *data, u16 length, void *p)
{
  pfcp_dl_flow_level_marking_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_dl_flow_level_marking");
  return 0;
}

static int encode_dl_flow_level_marking(void *p, u8 **vec)
{
  pfcp_dl_flow_level_marking_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_dl_flow_level_marking");
  return 0;
}

static int decode_header_enrichment(u8 *data, u16 length, void *p)
{
  pfcp_header_enrichment_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_header_enrichment");
  return 0;
}

static int encode_header_enrichment(void *p, u8 **vec)
{
  pfcp_header_enrichment_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_header_enrichment");
  return 0;
}

static int decode_measurement_information(u8 *data, u16 length, void *p)
{
  pfcp_measurement_information_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_measurement_information");
  return 0;
}

static int encode_measurement_information(void *p, u8 **vec)
{
  pfcp_measurement_information_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_measurement_information");
  return 0;
}

static int decode_node_report_type(u8 *data, u16 length, void *p)
{
  pfcp_node_report_type_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_node_report_type");
  return 0;
}

static int encode_node_report_type(void *p, u8 **vec)
{
  pfcp_node_report_type_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_node_report_type");
  return 0;
}

static int decode_remote_gtp_u_peer(u8 *data, u16 length, void *p)
{
  pfcp_remote_gtp_u_peer_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_remote_gtp_u_peer");
  return 0;
}

static int encode_remote_gtp_u_peer(void *p, u8 **vec)
{
  pfcp_remote_gtp_u_peer_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_remote_gtp_u_peer");
  return 0;
}

static int decode_ur_seqn(u8 *data, u16 length, void *p)
{
  pfcp_ur_seqn_t *v = p;

  if (length < 4)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u32(data);

  pfcp_debug ("PFCP: UR SeqN: %d (%p).", *v, v);
  return 0;
}

static int encode_ur_seqn(void *p, u8 **vec)
{
  pfcp_ur_seqn_t *v = p;

  pfcp_debug ("PFCP: UR SeqN: %d.", *v);

  put_u32(*vec, *v);
  return 0;
}

static int decode_activate_predefined_rules(u8 *data, u16 length, void *p)
{
  pfcp_activate_predefined_rules_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_activate_predefined_rules");
  return 0;
}

static int encode_activate_predefined_rules(void *p, u8 **vec)
{
  pfcp_activate_predefined_rules_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_activate_predefined_rules");
  return 0;
}

static int decode_deactivate_predefined_rules(u8 *data, u16 length, void *p)
{
  pfcp_deactivate_predefined_rules_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_deactivate_predefined_rules");
  return 0;
}

static int encode_deactivate_predefined_rules(void *p, u8 **vec)
{
  pfcp_deactivate_predefined_rules_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_deactivate_predefined_rules");
  return 0;
}

static int decode_far_id(u8 *data, u16 length, void *p)
{
  pfcp_far_id_t *v = p;

  if (length < 4)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u32(data);

  pfcp_debug ("PFCP: FAR Id: %d.", *v);
  return 0;
}

static int encode_far_id(void *p, u8 **vec)
{
  pfcp_far_id_t *v = p;

  pfcp_debug ("PFCP: FAR Id: %d.", *v);

  put_u32(*vec, *v);
  return 0;
}

static int decode_qer_id(u8 *data, u16 length, void *p)
{
  pfcp_qer_id_t *v = p;

  if (length < 4)
    return PFCP_CAUSE_INVALID_LENGTH;

  *v = get_u32(data);

  pfcp_debug ("PFCP: QER Id: %d.", *v);
  return 0;
}

static int encode_qer_id(void *p, u8 **vec)
{
  pfcp_qer_id_t *v = p;

  pfcp_debug ("PFCP: QER Id: %d.", *v);

  put_u32(*vec, *v);
  return 0;
}

static int decode_oci_flags(u8 *data, u16 length, void *p)
{
  pfcp_oci_flags_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_oci_flags");
  return 0;
}

static int encode_oci_flags(void *p, u8 **vec)
{
  pfcp_oci_flags_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_oci_flags");
  return 0;
}

static int decode_sx_association_release_request(u8 *data, u16 length, void *p)
{
  pfcp_sx_association_release_request_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_sx_association_release_request");
  return 0;
}

static int encode_sx_association_release_request(void *p, u8 **vec)
{
  pfcp_sx_association_release_request_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_sx_association_release_request");
  return 0;
}

static int decode_graceful_release_period(u8 *data, u16 length, void *p)
{
  pfcp_graceful_release_period_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_graceful_release_period");
  return 0;
}

static int encode_graceful_release_period(void *p, u8 **vec)
{
  pfcp_graceful_release_period_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_graceful_release_period");
  return 0;
}

static int decode_pdn_type(u8 *data, u16 length, void *p)
{
  pfcp_pdn_type_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_pdn_type");
  return 0;
}

static int encode_pdn_type(void *p, u8 **vec)
{
  pfcp_pdn_type_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_pdn_type");
  return 0;
}

static int decode_failed_rule_id(u8 *data, u16 length, void *p)
{
  pfcp_failed_rule_id_t *v = p;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  v->type = get_u8(data);
  length--;

  switch (v->type) {
  case FAILED_RULE_TYPE_PDR:
    if (length < 2)
      return PFCP_CAUSE_INVALID_LENGTH;
    v->id = get_u16(data);
    break;

  case FAILED_RULE_TYPE_FAR:
    if (length < 4)
      return PFCP_CAUSE_INVALID_LENGTH;
    v->id = get_u32(data);
    break;

  case FAILED_RULE_TYPE_QER:
    if (length < 4)
      return PFCP_CAUSE_INVALID_LENGTH;
    v->id = get_u32(data);
    break;

  case FAILED_RULE_TYPE_URR:
    if (length < 4)
      return PFCP_CAUSE_INVALID_LENGTH;
    v->id = get_u32(data);
    break;

  case FAILED_RULE_TYPE_BAR:
    if (length < 1)
      return PFCP_CAUSE_INVALID_LENGTH;
    v->id = get_u8(data);
    break;

  default:
    if (length < 4)
      return PFCP_CAUSE_INVALID_LENGTH;
    v->id = get_u32(data);
    break;
  }
  return 0;
}

static int encode_failed_rule_id(void *p, u8 **vec)
{
  pfcp_failed_rule_id_t *v = p;

  pfcp_debug ("PFCP: Failed Rule: Type: %d, Id: %d.", v->type, v->id);

  put_u8(*vec, v->type);
  switch (v->type) {
  case FAILED_RULE_TYPE_PDR:
    put_u16(*vec, v->id);
    break;

  case FAILED_RULE_TYPE_FAR:
    put_u32(*vec, v->id);
    break;

  case FAILED_RULE_TYPE_QER:
    put_u32(*vec, v->id);
    break;

  case FAILED_RULE_TYPE_URR:
    put_u32(*vec, v->id);
    break;

  case FAILED_RULE_TYPE_BAR:
    put_u8(*vec, v->id);
    break;

  default:
    put_u32(*vec, v->id);
    break;
  }
  return 0;
}

static int decode_time_quota_mechanism(u8 *data, u16 length, void *p)
{
  pfcp_time_quota_mechanism_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO decode_time_quota_mechanism");
  return 0;
}

static int encode_time_quota_mechanism(void *p, u8 **vec)
{
  pfcp_time_quota_mechanism_t *v __attribute__ ((unused)) = p;

  pfcp_warning ("PFCP: TODO encode_time_quota_mechanism");
  return 0;
}

u8 *
format_user_plane_ip_resource_information(u8 * s, va_list * args)
{
  pfcp_user_plane_ip_resource_information_t *i =
    va_arg (*args, pfcp_user_plane_ip_resource_information_t *);

  if (i->network_instance)
    s = format(s, "Network Instance: %U, ",
	       format_network_instance, i->network_instance);

  if (i->flags & USER_PLANE_IP_RESOURCE_INFORMATION_V4)
    s = format(s, "%U, ", format_ip4_address, &i->ip4);
  if (i->flags & USER_PLANE_IP_RESOURCE_INFORMATION_V6)
    s = format(s, "%U, ", format_ip6_address, &i->ip6);

  if (i->teid_range_indication != 0)
    s = format(s, "teid: 0x%02x000000/%d", i->teid_range, i->teid_range_indication);
  else
    _vec_len(s) -= 2;

  return s;
}

static int decode_user_plane_ip_resource_information(u8 *data, u16 length, void *p)
{
  pfcp_user_plane_ip_resource_information_t *v = p;
  u8 flags;

  if (length < 1)
    return PFCP_CAUSE_INVALID_LENGTH;

  flags = get_u8(data);
  v->flags = flags & 0x03;
  length--;

  v->teid_range_indication = (flags >> 2) & 0x07;
  if (v->teid_range_indication != 0)
    {
      if (length < 1)
	return PFCP_CAUSE_INVALID_LENGTH;

      v->teid_range = get_u8(data);
      length--;
    }

  if (flags & USER_PLANE_IP_RESOURCE_INFORMATION_V4)
    {
      if (length < 4)
	return PFCP_CAUSE_INVALID_LENGTH;
      get_ip4(v->ip4, data);
      length -= 4;
    }

  if (flags & USER_PLANE_IP_RESOURCE_INFORMATION_V6)
    {
      if (length < 16)
	return PFCP_CAUSE_INVALID_LENGTH;
      get_ip6(v->ip6, data);
      length -= 16;
    }

  if (flags & USER_PLANE_IP_RESOURCE_INFORMATION_ASSOCNI)
    {
      vec_reset_length(v->network_instance);
      vec_add(v->network_instance, data, length);
    }

  pfcp_debug ("PFCP: User Plane IP Resource Information: '%U'",
	      format_user_plane_ip_resource_information, v);
  return 0;
}

static int encode_user_plane_ip_resource_information(void *p, u8 **vec)
{
  pfcp_user_plane_ip_resource_information_t *v = p;
  u8 flags;

  pfcp_debug ("PFCP: User Plane IP Resource Information: '%U'",
	      format_user_plane_ip_resource_information, v);

  flags = v->flags;
  flags |= (v->teid_range_indication & 0x07) << 2;
  flags |= v->network_instance ? USER_PLANE_IP_RESOURCE_INFORMATION_ASSOCNI : 0;

  put_u8(*vec, flags);

  if (v->teid_range_indication != 0)
    put_u8(*vec, v->teid_range);

  if (v->flags & USER_PLANE_IP_RESOURCE_INFORMATION_V4)
    put_ip4(*vec, v->ip4);

  if (v->flags & USER_PLANE_IP_RESOURCE_INFORMATION_V6)
    put_ip6(*vec, v->ip6);

  if (v->network_instance)
    vec_append(*vec, v->network_instance);

  return 0;
}

static void free_user_plane_ip_resource_information(void *p)
{
  pfcp_user_plane_ip_resource_information_t *v = p;

  vec_free(v->network_instance);
}

/* Grouped Information Elements */


/**********************************************************/

static struct pfcp_group_ie_def pfcp_create_pdr_group[] =
  {
    [CREATE_PDR_PDR_ID] = {
      .type = PFCP_IE_PDR_ID,
      .offset = offsetof(pfcp_create_pdr_t, pdr_id)
    },
    [CREATE_PDR_PRECEDENCE] = {
      .type = PFCP_IE_PRECEDENCE,
      .offset = offsetof(pfcp_create_pdr_t, precedence)
    },
    [CREATE_PDR_PDI] = {
      .type = PFCP_IE_PDI,
      .offset = offsetof(pfcp_create_pdr_t, pdi)
    },
    [CREATE_PDR_OUTER_HEADER_REMOVAL] = {
      .type = PFCP_IE_OUTER_HEADER_REMOVAL,
      .offset = offsetof(pfcp_create_pdr_t, outer_header_removal)
    },
    [CREATE_PDR_FAR_ID] = {
      .type = PFCP_IE_FAR_ID,
      .offset = offsetof(pfcp_create_pdr_t, far_id)
    },
    [CREATE_PDR_URR_ID] = {
      .type = PFCP_IE_URR_ID,
      .is_array = true,
      .offset = offsetof(pfcp_create_pdr_t, urr_id)
    },
    [CREATE_PDR_QER_ID] = {
      .type = PFCP_IE_QER_ID,
      .is_array = true,
      .offset = offsetof(pfcp_create_pdr_t, qer_id)
    },
    [CREATE_PDR_ACTIVATE_PREDEFINED_RULES] = {
      .type = PFCP_IE_ACTIVATE_PREDEFINED_RULES,
      .offset = offsetof(pfcp_create_pdr_t, activate_predefined_rules)
    },
  };

static struct pfcp_group_ie_def pfcp_pdi_group[] =
  {
    [PDI_SOURCE_INTERFACE] = {
      .type = PFCP_IE_SOURCE_INTERFACE,
      .offset = offsetof(pfcp_pdi_t, source_interface)
    },
    [PDI_F_TEID] = {
      .type = PFCP_IE_F_TEID,
      .offset = offsetof(pfcp_pdi_t, f_teid)
    },
    [PDI_NETWORK_INSTANCE] = {
      .type = PFCP_IE_NETWORK_INSTANCE,
      .offset = offsetof(pfcp_pdi_t, network_instance)
    },
    [PDI_UE_IP_ADDRESS] = {
      .type = PFCP_IE_UE_IP_ADDRESS,
      .offset = offsetof(pfcp_pdi_t, ue_ip_address)
    },
    [PDI_SDF_FILTER] = {
      .type = PFCP_IE_SDF_FILTER,
      .offset = offsetof(pfcp_pdi_t, sdf_filter)
    },
    [PDI_APPLICATION_ID] = {
      .type = PFCP_IE_APPLICATION_ID,
      .offset = offsetof(pfcp_pdi_t, application_id)
    },
  };

static struct pfcp_group_ie_def pfcp_create_far_group[] =
  {
    [CREATE_FAR_FAR_ID] = {
      .type = PFCP_IE_FAR_ID,
      .offset = offsetof(pfcp_create_far_t, far_id)
    },
    [CREATE_FAR_APPLY_ACTION] = {
      .type = PFCP_IE_APPLY_ACTION,
      .offset = offsetof(pfcp_create_far_t, apply_action)
    },
    [CREATE_FAR_FORWARDING_PARAMETERS] = {
      .type = PFCP_IE_FORWARDING_PARAMETERS,
      .offset = offsetof(pfcp_create_far_t, forwarding_parameters)
    },
    [CREATE_FAR_DUPLICATING_PARAMETERS] = {
      .type = PFCP_IE_DUPLICATING_PARAMETERS,
      .offset = offsetof(pfcp_create_far_t, duplicating_parameters)
    },
    [CREATE_FAR_BAR_ID] = {
      .type = PFCP_IE_BAR_ID,
      .offset = offsetof(pfcp_create_far_t, bar_id)
    },
  };

static struct pfcp_group_ie_def pfcp_forwarding_parameters_group[] =
  {
    [FORWARDING_PARAMETERS_DESTINATION_INTERFACE] = {
      .type = PFCP_IE_DESTINATION_INTERFACE,
      .offset = offsetof(pfcp_forwarding_parameters_t, destination_interface)
    },
    [FORWARDING_PARAMETERS_NETWORK_INSTANCE] = {
      .type = PFCP_IE_NETWORK_INSTANCE,
      .offset = offsetof(pfcp_forwarding_parameters_t, network_instance)
    },
    [FORWARDING_PARAMETERS_REDIRECT_INFORMATION] = {
      .type = PFCP_IE_REDIRECT_INFORMATION,
      .offset = offsetof(pfcp_forwarding_parameters_t, redirect_information)
    },
    [FORWARDING_PARAMETERS_OUTER_HEADER_CREATION] = {
      .type = PFCP_IE_OUTER_HEADER_CREATION,
      .offset = offsetof(pfcp_forwarding_parameters_t, outer_header_creation)
    },
    [FORWARDING_PARAMETERS_TRANSPORT_LEVEL_MARKING] = {
      .type = PFCP_IE_TRANSPORT_LEVEL_MARKING,
      .offset = offsetof(pfcp_forwarding_parameters_t, transport_level_marking)
    },
    [FORWARDING_PARAMETERS_FORWARDING_POLICY] = {
      .type = PFCP_IE_FORWARDING_POLICY,
      .offset = offsetof(pfcp_forwarding_parameters_t, forwarding_policy)
    },
    [FORWARDING_PARAMETERS_HEADER_ENRICHMENT] = {
      .type = PFCP_IE_HEADER_ENRICHMENT,
      .offset = offsetof(pfcp_forwarding_parameters_t, header_enrichment)
    },
  };

static struct pfcp_group_ie_def pfcp_duplicating_parameters_group[] =
  {
    [DUPLICATING_PARAMETERS_DESTINATION_INTERFACE] = {
      .type = PFCP_IE_DESTINATION_INTERFACE,
      .offset = offsetof(pfcp_duplicating_parameters_t, destination_interface)
    },
    [DUPLICATING_PARAMETERS_OUTER_HEADER_CREATION] = {
      .type = PFCP_IE_OUTER_HEADER_CREATION,
      .offset = offsetof(pfcp_duplicating_parameters_t, outer_header_creation)
    },
    [DUPLICATING_PARAMETERS_TRANSPORT_LEVEL_MARKING] = {
      .type = PFCP_IE_TRANSPORT_LEVEL_MARKING,
      .offset = offsetof(pfcp_duplicating_parameters_t, transport_level_marking)
    },
    [DUPLICATING_PARAMETERS_FORWARDING_POLICY] = {
      .type = PFCP_IE_FORWARDING_POLICY,
      .offset = offsetof(pfcp_duplicating_parameters_t, forwarding_policy)
    },
  };

static struct pfcp_group_ie_def pfcp_create_urr_group[] =
  {
    [CREATE_URR_URR_ID] = {
      .type = PFCP_IE_URR_ID,
      .offset = offsetof(pfcp_create_urr_t, urr_id)
    },
    [CREATE_URR_MEASUREMENT_METHOD] = {
      .type = PFCP_IE_MEASUREMENT_METHOD,
      .offset = offsetof(pfcp_create_urr_t, measurement_method)
    },
    [CREATE_URR_REPORTING_TRIGGERS] = {
      .type = PFCP_IE_REPORTING_TRIGGERS,
      .offset = offsetof(pfcp_create_urr_t, reporting_triggers)
    },
    [CREATE_URR_MEASUREMENT_PERIOD] = {
      .type = PFCP_IE_MEASUREMENT_PERIOD,
      .offset = offsetof(pfcp_create_urr_t, measurement_period)
    },
    [CREATE_URR_VOLUME_THRESHOLD] = {
      .type = PFCP_IE_VOLUME_THRESHOLD,
      .offset = offsetof(pfcp_create_urr_t, volume_threshold)
    },
    [CREATE_URR_VOLUME_QUOTA] = {
      .type = PFCP_IE_VOLUME_QUOTA,
      .offset = offsetof(pfcp_create_urr_t, volume_quota)
    },
    [CREATE_URR_TIME_THRESHOLD] = {
      .type = PFCP_IE_TIME_THRESHOLD,
      .offset = offsetof(pfcp_create_urr_t, time_threshold)
    },
    [CREATE_URR_TIME_QUOTA] = {
      .type = PFCP_IE_TIME_QUOTA,
      .offset = offsetof(pfcp_create_urr_t, time_quota)
    },
    [CREATE_URR_QUOTA_HOLDING_TIME] = {
      .type = PFCP_IE_QUOTA_HOLDING_TIME,
      .offset = offsetof(pfcp_create_urr_t, quota_holding_time)
    },
    [CREATE_URR_DROPPED_DL_TRAFFIC_THRESHOLD] = {
      .type = PFCP_IE_DROPPED_DL_TRAFFIC_THRESHOLD,
      .offset = offsetof(pfcp_create_urr_t, dropped_dl_traffic_threshold)
    },
    [CREATE_URR_MONITORING_TIME] = {
      .type = PFCP_IE_MONITORING_TIME,
      .offset = offsetof(pfcp_create_urr_t, monitoring_time)
    },
    [CREATE_URR_SUBSEQUENT_VOLUME_THRESHOLD] = {
      .type = PFCP_IE_SUBSEQUENT_VOLUME_THRESHOLD,
      .offset = offsetof(pfcp_create_urr_t, subsequent_volume_threshold)
    },
    [CREATE_URR_SUBSEQUENT_TIME_THRESHOLD] = {
      .type = PFCP_IE_SUBSEQUENT_TIME_THRESHOLD,
      .offset = offsetof(pfcp_create_urr_t, subsequent_time_threshold)
    },
    [CREATE_URR_INACTIVITY_DETECTION_TIME] = {
      .type = PFCP_IE_INACTIVITY_DETECTION_TIME,
      .offset = offsetof(pfcp_create_urr_t, inactivity_detection_time)
    },
    [CREATE_URR_LINKED_URR_ID] = {
      .type = PFCP_IE_LINKED_URR_ID,
      .offset = offsetof(pfcp_create_urr_t, linked_urr_id)
    },
    [CREATE_URR_MEASUREMENT_INFORMATION] = {
      .type = PFCP_IE_MEASUREMENT_INFORMATION,
      .offset = offsetof(pfcp_create_urr_t, measurement_information)
    },
    [CREATE_URR_TIME_QUOTA_MECHANISM] = {
      .type = PFCP_IE_TIME_QUOTA_MECHANISM,
      .offset = offsetof(pfcp_create_urr_t, time_quota_mechanism)
    },
  };

static struct pfcp_group_ie_def pfcp_create_qer_group[] =
  {
    [CREATE_QER_QER_ID] = {
      .type = PFCP_IE_QER_ID,
      .offset = offsetof(pfcp_create_qer_t, qer_id)
    },
    [CREATE_QER_QER_CORRELATION_ID] = {
      .type = PFCP_IE_QER_CORRELATION_ID,
      .offset = offsetof(pfcp_create_qer_t, qer_correlation_id)
    },
    [CREATE_QER_GATE_STATUS] = {
      .type = PFCP_IE_GATE_STATUS,
      .offset = offsetof(pfcp_create_qer_t, gate_status)
    },
    [CREATE_QER_MBR] = {
      .type = PFCP_IE_MBR,
      .offset = offsetof(pfcp_create_qer_t, mbr)
    },
    [CREATE_QER_GBR] = {
      .type = PFCP_IE_GBR,
      .offset = offsetof(pfcp_create_qer_t, gbr)
    },
    [CREATE_QER_PACKET_RATE] = {
      .type = PFCP_IE_PACKET_RATE,
      .offset = offsetof(pfcp_create_qer_t, packet_rate)
    },
    [CREATE_QER_DL_FLOW_LEVEL_MARKING] = {
      .type = PFCP_IE_DL_FLOW_LEVEL_MARKING,
      .offset = offsetof(pfcp_create_qer_t, dl_flow_level_marking)
    },
  };

static struct pfcp_group_ie_def pfcp_created_pdr_group[] =
  {
    [CREATED_PDR_PDR_ID] = {
      .type = PFCP_IE_PDR_ID,
      .offset = offsetof(pfcp_created_pdr_t, pdr_id)
    },
    [CREATED_PDR_F_TEID] = {
      .type = PFCP_IE_F_TEID,
      .offset = offsetof(pfcp_created_pdr_t, f_teid)
    },
  };

static struct pfcp_group_ie_def pfcp_update_pdr_group[] =
  {
    [UPDATE_PDR_PDR_ID] = {
      .type = PFCP_IE_PDR_ID,
      .offset = offsetof(pfcp_update_pdr_t, pdr_id)
    },
    [UPDATE_PDR_OUTER_HEADER_REMOVAL] = {
      .type = PFCP_IE_OUTER_HEADER_REMOVAL,
      .offset = offsetof(pfcp_update_pdr_t, outer_header_removal)
    },
    [UPDATE_PDR_PRECEDENCE] = {
      .type = PFCP_IE_PRECEDENCE,
      .offset = offsetof(pfcp_update_pdr_t, precedence)
    },
    [UPDATE_PDR_PDI] = {
      .type = PFCP_IE_PDI,
      .offset = offsetof(pfcp_update_pdr_t, pdi)
    },
    [UPDATE_PDR_FAR_ID] = {
      .type = PFCP_IE_FAR_ID,
      .offset = offsetof(pfcp_update_pdr_t, far_id)
    },
    [UPDATE_PDR_URR_ID] = {
      .type = PFCP_IE_URR_ID,
      .is_array = true,
      .offset = offsetof(pfcp_update_pdr_t, urr_id)
    },
    [UPDATE_PDR_QER_ID] = {
      .type = PFCP_IE_QER_ID,
      .is_array = true,
      .offset = offsetof(pfcp_update_pdr_t, qer_id)
    },
    [UPDATE_PDR_ACTIVATE_PREDEFINED_RULES] = {
      .type = PFCP_IE_ACTIVATE_PREDEFINED_RULES,
      .offset = offsetof(pfcp_update_pdr_t, activate_predefined_rules)
    },
    [UPDATE_PDR_DEACTIVATE_PREDEFINED_RULES] = {
      .type = PFCP_IE_DEACTIVATE_PREDEFINED_RULES,
      .offset = offsetof(pfcp_update_pdr_t, deactivate_predefined_rules)
    },
  };

static struct pfcp_group_ie_def pfcp_update_far_group[] =
  {
    [UPDATE_FAR_FAR_ID] = {
      .type = PFCP_IE_FAR_ID,
      .offset = offsetof(pfcp_update_far_t, far_id)
    },
    [UPDATE_FAR_APPLY_ACTION] = {
      .type = PFCP_IE_APPLY_ACTION,
      .offset = offsetof(pfcp_update_far_t, apply_action)
    },
    [UPDATE_FAR_UPDATE_FORWARDING_PARAMETERS] = {
      .type = PFCP_IE_UPDATE_FORWARDING_PARAMETERS,
      .offset = offsetof(pfcp_update_far_t, update_forwarding_parameters)
    },
    [UPDATE_FAR_UPDATE_DUPLICATING_PARAMETERS] = {
      .type = PFCP_IE_UPDATE_DUPLICATING_PARAMETERS,
      .offset = offsetof(pfcp_update_far_t, update_duplicating_parameters)
    },
    [UPDATE_FAR_BAR_ID] = {
      .type = PFCP_IE_BAR_ID,
      .offset = offsetof(pfcp_update_far_t, bar_id)
    },
  };

static struct pfcp_group_ie_def pfcp_update_forwarding_parameters_group[] =
  {
    [UPDATE_FORWARDING_PARAMETERS_DESTINATION_INTERFACE] = {
      .type = PFCP_IE_DESTINATION_INTERFACE,
      .offset = offsetof(pfcp_update_forwarding_parameters_t, destination_interface)
    },
    [UPDATE_FORWARDING_PARAMETERS_NETWORK_INSTANCE] = {
      .type = PFCP_IE_NETWORK_INSTANCE,
      .offset = offsetof(pfcp_update_forwarding_parameters_t, network_instance)
    },
    [UPDATE_FORWARDING_PARAMETERS_REDIRECT_INFORMATION] = {
      .type = PFCP_IE_REDIRECT_INFORMATION,
      .offset = offsetof(pfcp_update_forwarding_parameters_t, redirect_information)
    },
    [UPDATE_FORWARDING_PARAMETERS_OUTER_HEADER_CREATION] = {
      .type = PFCP_IE_OUTER_HEADER_CREATION,
      .offset = offsetof(pfcp_update_forwarding_parameters_t, outer_header_creation)
    },
    [UPDATE_FORWARDING_PARAMETERS_TRANSPORT_LEVEL_MARKING] = {
      .type = PFCP_IE_TRANSPORT_LEVEL_MARKING,
      .offset = offsetof(pfcp_update_forwarding_parameters_t, transport_level_marking)
    },
    [UPDATE_FORWARDING_PARAMETERS_FORWARDING_POLICY] = {
      .type = PFCP_IE_FORWARDING_POLICY,
      .offset = offsetof(pfcp_update_forwarding_parameters_t, forwarding_policy)
    },
    [UPDATE_FORWARDING_PARAMETERS_HEADER_ENRICHMENT] = {
      .type = PFCP_IE_HEADER_ENRICHMENT,
      .offset = offsetof(pfcp_update_forwarding_parameters_t, header_enrichment)
    },
    [UPDATE_FORWARDING_PARAMETERS_SXSMREQ_FLAGS] = {
      .type = PFCP_IE_SXSMREQ_FLAGS,
      .offset = offsetof(pfcp_update_forwarding_parameters_t, sxsmreq_flags)
    },
  };

static struct pfcp_group_ie_def pfcp_update_bar_response_group[] =
  {
    [UPDATE_BAR_RESPONSE_BAR_ID] = {
      .type = PFCP_IE_BAR_ID,
      .offset = offsetof(pfcp_update_bar_response_t, bar_id)
    },
    [UPDATE_BAR_RESPONSE_DOWNLINK_DATA_NOTIFICATION_DELAY] = {
      .type = PFCP_IE_DOWNLINK_DATA_NOTIFICATION_DELAY,
      .offset = offsetof(pfcp_update_bar_response_t, downlink_data_notification_delay)
    },
    [UPDATE_BAR_RESPONSE_DL_BUFFERING_DURATION] = {
      .type = PFCP_IE_DL_BUFFERING_DURATION,
      .offset = offsetof(pfcp_update_bar_response_t, dl_buffering_duration)
    },
    [UPDATE_BAR_RESPONSE_DL_BUFFERING_SUGGESTED_PACKET_COUNT] = {
      .type = PFCP_IE_DL_BUFFERING_SUGGESTED_PACKET_COUNT,
      .offset = offsetof(pfcp_update_bar_response_t, dl_buffering_suggested_packet_count)
    },
  };

static struct pfcp_group_ie_def pfcp_update_urr_group[] =
  {
    [UPDATE_URR_URR_ID] = {
      .type = PFCP_IE_URR_ID,
      .offset = offsetof(pfcp_update_urr_t, urr_id)
    },
    [UPDATE_URR_MEASUREMENT_METHOD] = {
      .type = PFCP_IE_MEASUREMENT_METHOD,
      .offset = offsetof(pfcp_update_urr_t, measurement_method)
    },
    [UPDATE_URR_REPORTING_TRIGGERS] = {
      .type = PFCP_IE_REPORTING_TRIGGERS,
      .offset = offsetof(pfcp_update_urr_t, reporting_triggers)
    },
    [UPDATE_URR_MEASUREMENT_PERIOD] = {
      .type = PFCP_IE_MEASUREMENT_PERIOD,
      .offset = offsetof(pfcp_update_urr_t, measurement_period)
    },
    [UPDATE_URR_VOLUME_THRESHOLD] = {
      .type = PFCP_IE_VOLUME_THRESHOLD,
      .offset = offsetof(pfcp_update_urr_t, volume_threshold)
    },
    [UPDATE_URR_VOLUME_QUOTA] = {
      .type = PFCP_IE_VOLUME_QUOTA,
      .offset = offsetof(pfcp_update_urr_t, volume_quota)
    },
    [UPDATE_URR_TIME_THRESHOLD] = {
      .type = PFCP_IE_TIME_THRESHOLD,
      .offset = offsetof(pfcp_update_urr_t, time_threshold)
    },
    [UPDATE_URR_TIME_QUOTA] = {
      .type = PFCP_IE_TIME_QUOTA,
      .offset = offsetof(pfcp_update_urr_t, time_quota)
    },
    [UPDATE_URR_QUOTA_HOLDING_TIME] = {
      .type = PFCP_IE_QUOTA_HOLDING_TIME,
      .offset = offsetof(pfcp_update_urr_t, quota_holding_time)
    },
    [UPDATE_URR_DROPPED_DL_TRAFFIC_THRESHOLD] = {
      .type = PFCP_IE_DROPPED_DL_TRAFFIC_THRESHOLD,
      .offset = offsetof(pfcp_update_urr_t, dropped_dl_traffic_threshold)
    },
    [UPDATE_URR_MONITORING_TIME] = {
      .type = PFCP_IE_MONITORING_TIME,
      .offset = offsetof(pfcp_update_urr_t, monitoring_time)
    },
    [UPDATE_URR_SUBSEQUENT_VOLUME_THRESHOLD] = {
      .type = PFCP_IE_SUBSEQUENT_VOLUME_THRESHOLD,
      .offset = offsetof(pfcp_update_urr_t, subsequent_volume_threshold)
    },
    [UPDATE_URR_SUBSEQUENT_TIME_THRESHOLD] = {
      .type = PFCP_IE_SUBSEQUENT_TIME_THRESHOLD,
      .offset = offsetof(pfcp_update_urr_t, subsequent_time_threshold)
    },
    [UPDATE_URR_INACTIVITY_DETECTION_TIME] = {
      .type = PFCP_IE_INACTIVITY_DETECTION_TIME,
      .offset = offsetof(pfcp_update_urr_t, inactivity_detection_time)
    },
    [UPDATE_URR_LINKED_URR_ID] = {
      .type = PFCP_IE_LINKED_URR_ID,
      .offset = offsetof(pfcp_update_urr_t, linked_urr_id)
    },
    [UPDATE_URR_MEASUREMENT_INFORMATION] = {
      .type = PFCP_IE_MEASUREMENT_INFORMATION,
      .offset = offsetof(pfcp_update_urr_t, measurement_information)
    },
    [UPDATE_URR_TIME_QUOTA_MECHANISM] = {
      .type = PFCP_IE_TIME_QUOTA_MECHANISM,
      .offset = offsetof(pfcp_update_urr_t, time_quota_mechanism)
    },
  };

static struct pfcp_group_ie_def pfcp_update_qer_group[] =
  {
    [UPDATE_QER_QER_ID] = {
      .type = PFCP_IE_QER_ID,
      .offset = offsetof(pfcp_update_qer_t, qer_id)
    },
    [UPDATE_QER_QER_CORRELATION_ID] = {
      .type = PFCP_IE_QER_CORRELATION_ID,
      .offset = offsetof(pfcp_update_qer_t, qer_correlation_id)
    },
    [UPDATE_QER_GATE_STATUS] = {
      .type = PFCP_IE_GATE_STATUS,
      .offset = offsetof(pfcp_update_qer_t, gate_status)
    },
    [UPDATE_QER_MBR] = {
      .type = PFCP_IE_MBR,
      .offset = offsetof(pfcp_update_qer_t, mbr)
    },
    [UPDATE_QER_GBR] = {
      .type = PFCP_IE_GBR,
      .offset = offsetof(pfcp_update_qer_t, gbr)
    },
    [UPDATE_QER_PACKET_RATE] = {
      .type = PFCP_IE_PACKET_RATE,
      .offset = offsetof(pfcp_update_qer_t, packet_rate)
    },
    [UPDATE_QER_DL_FLOW_LEVEL_MARKING] = {
      .type = PFCP_IE_DL_FLOW_LEVEL_MARKING,
      .offset = offsetof(pfcp_update_qer_t, dl_flow_level_marking)
    },
  };

static struct pfcp_group_ie_def pfcp_remove_pdr_group[] =
  {
    [REMOVE_PDR_PDR_ID] = {
      .type = PFCP_IE_PDR_ID,
      .offset = offsetof(pfcp_remove_pdr_t, pdr_id)
    },
  };

static struct pfcp_group_ie_def pfcp_remove_far_group[] =
  {
    [REMOVE_FAR_FAR_ID] = {
      .type = PFCP_IE_FAR_ID,
      .offset = offsetof(pfcp_remove_far_t, far_id)
    },
  };

static struct pfcp_group_ie_def pfcp_remove_urr_group[] =
  {
    [REMOVE_URR_URR_ID] = {
      .type = PFCP_IE_URR_ID,
      .offset = offsetof(pfcp_remove_urr_t, urr_id)
    },
  };

static struct pfcp_group_ie_def pfcp_remove_qer_group[] =
  {
    [REMOVE_QER_QER_ID] = {
      .type = PFCP_IE_QER_ID,
      .offset = offsetof(pfcp_remove_qer_t, qer_id)
    },
  };

static struct pfcp_group_ie_def pfcp_load_control_information_group[] =
  {
    [LOAD_CONTROL_INFORMATION_SEQUENCE_NUMBER] = {
      .type = PFCP_IE_SEQUENCE_NUMBER,
      .offset = offsetof(pfcp_load_control_information_t, sequence_number)
    },
    [LOAD_CONTROL_INFORMATION_METRIC] = {
      .type = PFCP_IE_METRIC,
      .offset = offsetof(pfcp_load_control_information_t, metric)
    },
  };

static struct pfcp_group_ie_def pfcp_overload_control_information_group[] =
  {
    [OVERLOAD_CONTROL_INFORMATION_SEQUENCE_NUMBER] = {
      .type = PFCP_IE_SEQUENCE_NUMBER,
      .offset = offsetof(pfcp_overload_control_information_t, sequence_number)
    },
    [OVERLOAD_CONTROL_INFORMATION_METRIC] = {
      .type = PFCP_IE_METRIC,
      .offset = offsetof(pfcp_overload_control_information_t, metric)
    },
    [OVERLOAD_CONTROL_INFORMATION_TIMER] = {
      .type = PFCP_IE_TIMER,
      .offset = offsetof(pfcp_overload_control_information_t, timer)
    },
    [OVERLOAD_CONTROL_INFORMATION_OCI_FLAGS] = {
      .type = PFCP_IE_OCI_FLAGS,
      .offset = offsetof(pfcp_overload_control_information_t, oci_flags)
    },
  };

static struct pfcp_group_ie_def pfcp_application_id_pfds_group[] =
  {
    [APPLICATION_ID_PFDS_APPLICATION_ID] = {
      .type = PFCP_IE_APPLICATION_ID,
      .offset = offsetof(pfcp_application_id_pfds_t, application_id)
    },
    [APPLICATION_ID_PFDS_PFD] = {
      .type = PFCP_IE_PFD,
      .is_array = true,
      .offset = offsetof(pfcp_application_id_pfds_t, pfd)
    },
  };

static struct pfcp_group_ie_def pfcp_pfd_group[] =
  {
    [PFD_PFD_CONTENTS] = {
      .type = PFCP_IE_PFD_CONTENTS,
      .is_array = true,
      .offset = offsetof(pfcp_pfd_t, pfd_contents)
    },
  };

static struct pfcp_group_ie_def pfcp_application_detection_information_group[] =
  {
    [APPLICATION_DETECTION_INFORMATION_APPLICATION_ID] = {
      .type = PFCP_IE_APPLICATION_ID,
      .offset = offsetof(pfcp_application_detection_information_t, application_id)
    },
    [APPLICATION_DETECTION_INFORMATION_APPLICATION_INSTANCE_ID] = {
      .type = PFCP_IE_APPLICATION_INSTANCE_ID,
      .offset = offsetof(pfcp_application_detection_information_t, application_instance_id)
    },
    [APPLICATION_DETECTION_INFORMATION_FLOW_INFORMATION] = {
      .type = PFCP_IE_FLOW_INFORMATION,
      .offset = offsetof(pfcp_application_detection_information_t, flow_information)
    },
  };

static struct pfcp_group_ie_def pfcp_query_urr_group[] =
  {
    [QUERY_URR_URR_ID] = {
      .type = PFCP_IE_URR_ID,
      .offset = offsetof(pfcp_query_urr_t, urr_id)
    },
  };

static struct pfcp_group_ie_def pfcp_usage_report_smr_group[] =
  {
    [USAGE_REPORT_URR_ID] = {
      .type = PFCP_IE_URR_ID,
      .offset = offsetof(pfcp_usage_report_t, urr_id)
    },
    [USAGE_REPORT_UR_SEQN] = {
      .type = PFCP_IE_UR_SEQN,
      .offset = offsetof(pfcp_usage_report_t, ur_seqn)
    },
    [USAGE_REPORT_USAGE_REPORT_TRIGGER] = {
      .type = PFCP_IE_USAGE_REPORT_TRIGGER,
      .offset = offsetof(pfcp_usage_report_t, usage_report_trigger)
    },
    [USAGE_REPORT_START_TIME] = {
      .type = PFCP_IE_START_TIME,
      .offset = offsetof(pfcp_usage_report_t, start_time)
    },
    [USAGE_REPORT_END_TIME] = {
      .type = PFCP_IE_END_TIME,
      .offset = offsetof(pfcp_usage_report_t, end_time)
    },
    [USAGE_REPORT_VOLUME_MEASUREMENT] = {
      .type = PFCP_IE_VOLUME_MEASUREMENT,
      .offset = offsetof(pfcp_usage_report_t, volume_measurement)
    },
    [USAGE_REPORT_DURATION_MEASUREMENT] = {
      .type = PFCP_IE_DURATION_MEASUREMENT,
      .offset = offsetof(pfcp_usage_report_t, duration_measurement)
    },
    [USAGE_REPORT_TIME_OF_FIRST_PACKET] = {
      .type = PFCP_IE_TIME_OF_FIRST_PACKET,
      .offset = offsetof(pfcp_usage_report_t, time_of_first_packet)
    },
    [USAGE_REPORT_TIME_OF_LAST_PACKET] = {
      .type = PFCP_IE_TIME_OF_LAST_PACKET,
      .offset = offsetof(pfcp_usage_report_t, time_of_last_packet)
    },
    [USAGE_REPORT_USAGE_INFORMATION] = {
      .type = PFCP_IE_USAGE_INFORMATION,
      .offset = offsetof(pfcp_usage_report_t, usage_information)
    },
  };

static struct pfcp_group_ie_def pfcp_usage_report_sdr_group[] =
  {
    [USAGE_REPORT_URR_ID] = {
      .type = PFCP_IE_URR_ID,
      .offset = offsetof(pfcp_usage_report_t, urr_id)
    },
    [USAGE_REPORT_UR_SEQN] = {
      .type = PFCP_IE_UR_SEQN,
      .offset = offsetof(pfcp_usage_report_t, ur_seqn)
    },
    [USAGE_REPORT_USAGE_REPORT_TRIGGER] = {
      .type = PFCP_IE_USAGE_REPORT_TRIGGER,
      .offset = offsetof(pfcp_usage_report_t, usage_report_trigger)
    },
    [USAGE_REPORT_START_TIME] = {
      .type = PFCP_IE_START_TIME,
      .offset = offsetof(pfcp_usage_report_t, start_time)
    },
    [USAGE_REPORT_END_TIME] = {
      .type = PFCP_IE_END_TIME,
      .offset = offsetof(pfcp_usage_report_t, end_time)
    },
    [USAGE_REPORT_VOLUME_MEASUREMENT] = {
      .type = PFCP_IE_VOLUME_MEASUREMENT,
      .offset = offsetof(pfcp_usage_report_t, volume_measurement)
    },
    [USAGE_REPORT_DURATION_MEASUREMENT] = {
      .type = PFCP_IE_DURATION_MEASUREMENT,
      .offset = offsetof(pfcp_usage_report_t, duration_measurement)
    },
    [USAGE_REPORT_TIME_OF_FIRST_PACKET] = {
      .type = PFCP_IE_TIME_OF_FIRST_PACKET,
      .offset = offsetof(pfcp_usage_report_t, time_of_first_packet)
    },
    [USAGE_REPORT_TIME_OF_LAST_PACKET] = {
      .type = PFCP_IE_TIME_OF_LAST_PACKET,
      .offset = offsetof(pfcp_usage_report_t, time_of_last_packet)
    },
    [USAGE_REPORT_USAGE_INFORMATION] = {
      .type = PFCP_IE_USAGE_INFORMATION,
      .offset = offsetof(pfcp_usage_report_t, usage_information)
    },
  };

static struct pfcp_group_ie_def pfcp_usage_report_srr_group[] =
  {
    [USAGE_REPORT_URR_ID] = {
      .type = PFCP_IE_URR_ID,
      .offset = offsetof(pfcp_usage_report_t, urr_id)
    },
    [USAGE_REPORT_UR_SEQN] = {
      .type = PFCP_IE_UR_SEQN,
      .offset = offsetof(pfcp_usage_report_t, ur_seqn)
    },
    [USAGE_REPORT_USAGE_REPORT_TRIGGER] = {
      .type = PFCP_IE_USAGE_REPORT_TRIGGER,
      .offset = offsetof(pfcp_usage_report_t, usage_report_trigger)
    },
    [USAGE_REPORT_START_TIME] = {
      .type = PFCP_IE_START_TIME,
      .offset = offsetof(pfcp_usage_report_t, start_time)
    },
    [USAGE_REPORT_END_TIME] = {
      .type = PFCP_IE_END_TIME,
      .offset = offsetof(pfcp_usage_report_t, end_time)
    },
    [USAGE_REPORT_VOLUME_MEASUREMENT] = {
      .type = PFCP_IE_VOLUME_MEASUREMENT,
      .offset = offsetof(pfcp_usage_report_t, volume_measurement)
    },
    [USAGE_REPORT_DURATION_MEASUREMENT] = {
      .type = PFCP_IE_DURATION_MEASUREMENT,
      .offset = offsetof(pfcp_usage_report_t, duration_measurement)
    },
    [USAGE_REPORT_APPLICATION_DETECTION_INFORMATION] = {
      .type = PFCP_IE_APPLICATION_DETECTION_INFORMATION,
      .offset = offsetof(pfcp_usage_report_t, application_detection_information)
    },
    [USAGE_REPORT_UE_IP_ADDRESS] = {
      .type = PFCP_IE_UE_IP_ADDRESS,
      .offset = offsetof(pfcp_usage_report_t, ue_ip_address)
    },
    [USAGE_REPORT_NETWORK_INSTANCE] = {
      .type = PFCP_IE_NETWORK_INSTANCE,
      .offset = offsetof(pfcp_usage_report_t, network_instance)
    },
    [USAGE_REPORT_TIME_OF_FIRST_PACKET] = {
      .type = PFCP_IE_TIME_OF_FIRST_PACKET,
      .offset = offsetof(pfcp_usage_report_t, time_of_first_packet)
    },
    [USAGE_REPORT_TIME_OF_LAST_PACKET] = {
      .type = PFCP_IE_TIME_OF_LAST_PACKET,
      .offset = offsetof(pfcp_usage_report_t, time_of_last_packet)
    },
    [USAGE_REPORT_USAGE_INFORMATION] = {
      .type = PFCP_IE_USAGE_INFORMATION,
      .offset = offsetof(pfcp_usage_report_t, usage_information)
    },
  };

static struct pfcp_group_ie_def pfcp_downlink_data_report_group[] =
  {
    [DOWNLINK_DATA_REPORT_PDR_ID] = {
      .type = PFCP_IE_PDR_ID,
      .is_array = true,
      .offset = offsetof(pfcp_downlink_data_report_t, pdr_id)
    },
    [DOWNLINK_DATA_REPORT_DOWNLINK_DATA_SERVICE_INFORMATION] = {
      .type = PFCP_IE_DOWNLINK_DATA_SERVICE_INFORMATION,
      .is_array = true,
      .offset = offsetof(pfcp_downlink_data_report_t, downlink_data_service_information)
    },
  };

static struct pfcp_group_ie_def pfcp_create_bar_group[] =
  {
    [CREATE_BAR_BAR_ID] = {
      .type = PFCP_IE_BAR_ID,
      .offset = offsetof(pfcp_create_bar_t, bar_id)
    },
    [CREATE_BAR_DOWNLINK_DATA_NOTIFICATION_DELAY] = {
      .type = PFCP_IE_DOWNLINK_DATA_NOTIFICATION_DELAY,
      .offset = offsetof(pfcp_create_bar_t, downlink_data_notification_delay)
    },
  };

static struct pfcp_group_ie_def pfcp_update_bar_request_group[] =
  {
    [UPDATE_BAR_REQUEST_BAR_ID] = {
      .type = PFCP_IE_BAR_ID,
      .offset = offsetof(pfcp_update_bar_request_t, bar_id)
    },
    [UPDATE_BAR_REQUEST_DOWNLINK_DATA_NOTIFICATION_DELAY] = {
      .type = PFCP_IE_DOWNLINK_DATA_NOTIFICATION_DELAY,
      .offset = offsetof(pfcp_update_bar_request_t, downlink_data_notification_delay)
    },
  };

static struct pfcp_group_ie_def pfcp_remove_bar_group[] =
  {
    [REMOVE_BAR_BAR_ID] = {
      .type = PFCP_IE_BAR_ID,
      .offset = offsetof(pfcp_remove_bar_t, bar_id)
    },
  };

static struct pfcp_group_ie_def pfcp_error_indication_report_group[] =
  {
    [ERROR_INDICATION_REPORT_F_TEID] = {
      .type = PFCP_IE_F_TEID,
      .is_array = true,
      .offset = offsetof(pfcp_error_indication_report_t, f_teid)
    },
  };

static struct pfcp_group_ie_def pfcp_user_plane_path_failure_report_group[] =
  {
    [USER_PLANE_PATH_FAILURE_REPORT_REMOTE_GTP_U_PEER] = {
      .type = PFCP_IE_REMOTE_GTP_U_PEER,
      .is_array = true,
      .offset = offsetof(pfcp_user_plane_path_failure_report_t, remote_gtp_u_peer)
    },
  };

static struct pfcp_group_ie_def pfcp_update_duplicating_parameters_group[] =
  {
    [UPDATE_DUPLICATING_PARAMETERS_DESTINATION_INTERFACE] = {
      .type = PFCP_IE_DESTINATION_INTERFACE,
      .offset = offsetof(pfcp_update_duplicating_parameters_t, destination_interface)
    },
    [UPDATE_DUPLICATING_PARAMETERS_OUTER_HEADER_CREATION] = {
      .type = PFCP_IE_OUTER_HEADER_CREATION,
      .offset = offsetof(pfcp_update_duplicating_parameters_t, outer_header_creation)
    },
    [UPDATE_DUPLICATING_PARAMETERS_TRANSPORT_LEVEL_MARKING] = {
      .type = PFCP_IE_TRANSPORT_LEVEL_MARKING,
      .offset = offsetof(pfcp_update_duplicating_parameters_t, transport_level_marking)
    },
    [UPDATE_DUPLICATING_PARAMETERS_FORWARDING_POLICY] = {
      .type = PFCP_IE_FORWARDING_POLICY,
      .offset = offsetof(pfcp_update_duplicating_parameters_t, forwarding_policy)
    },
  };

/**********************************************************/

#define SIMPLE_IE(IE, TYPE)				\
  [IE] = {						\
    .length = sizeof(pfcp_ ## TYPE ## _t),		\
    .decode = decode_ ## TYPE,				\
    .encode = encode_ ## TYPE,				\
}

#define SIMPLE_IE_FREE(IE, TYPE)			\
  [IE] = {						\
    .length = sizeof(pfcp_ ## TYPE ## _t),		\
    .decode = decode_ ## TYPE,				\
    .encode = encode_ ## TYPE,				\
    .free = free_ ## TYPE,				\
}

static struct pfcp_ie_def group_specs[] =
  {
    [PFCP_IE_CREATE_PDR] =
    {
      .length = sizeof(pfcp_create_pdr_t),
      .mandatory = (BIT(CREATE_PDR_PDR_ID) |
		    BIT(CREATE_PDR_PRECEDENCE) |
		    BIT(CREATE_PDR_PDI)),
      .size = ARRAY_LEN(pfcp_create_pdr_group),
      .group = pfcp_create_pdr_group,
    },
    [PFCP_IE_PDI] =
    {
      .length = sizeof(pfcp_pdi_t),
      .mandatory = BIT(PDI_SOURCE_INTERFACE),
      .size = ARRAY_LEN(pfcp_pdi_group),
      .group = pfcp_pdi_group,
    },
    [PFCP_IE_CREATE_FAR] =
    {
      .length = sizeof(pfcp_create_far_t),
      .mandatory = (BIT(CREATE_FAR_FAR_ID) |
		    BIT(CREATE_FAR_APPLY_ACTION)),
      .size = ARRAY_LEN(pfcp_create_far_group),
      .group = pfcp_create_far_group,
    },
    [PFCP_IE_FORWARDING_PARAMETERS] =
    {
      .length = sizeof(pfcp_forwarding_parameters_t),
      .mandatory = BIT(FORWARDING_PARAMETERS_DESTINATION_INTERFACE),
      .size = ARRAY_LEN(pfcp_forwarding_parameters_group),
      .group = pfcp_forwarding_parameters_group,
    },
    [PFCP_IE_DUPLICATING_PARAMETERS] =
    {
      .length = sizeof(pfcp_duplicating_parameters_t),
      .mandatory = BIT(DUPLICATING_PARAMETERS_DESTINATION_INTERFACE),
      .size = ARRAY_LEN(pfcp_duplicating_parameters_group),
      .group = pfcp_duplicating_parameters_group,
    },
    [PFCP_IE_CREATE_URR] =
    {
      .length = sizeof(pfcp_create_urr_t),
      .mandatory = (BIT(CREATE_URR_URR_ID) |
		    BIT(CREATE_URR_MEASUREMENT_METHOD)),
      .size = ARRAY_LEN(pfcp_create_urr_group),
      .group = pfcp_create_urr_group,
    },
    [PFCP_IE_CREATE_QER] =
    {
      .length = sizeof(pfcp_create_qer_t),
      .mandatory = (BIT(CREATE_QER_QER_ID) |
		    BIT(CREATE_QER_GATE_STATUS)),
      .size = ARRAY_LEN(pfcp_create_qer_group),
      .group = pfcp_create_qer_group,
    },
    [PFCP_IE_CREATED_PDR] =
    {
      .length = sizeof(pfcp_created_pdr_t),
      .mandatory = BIT(CREATED_PDR_PDR_ID),
      .size = ARRAY_LEN(pfcp_created_pdr_group),
      .group = pfcp_created_pdr_group,
    },
    [PFCP_IE_UPDATE_PDR] =
    {
      .length = sizeof(pfcp_update_pdr_t),
      .mandatory = BIT(UPDATE_PDR_PDR_ID),
      .size = ARRAY_LEN(pfcp_update_pdr_group),
      .group = pfcp_update_pdr_group,
    },
    [PFCP_IE_UPDATE_FAR] =
    {
      .length = sizeof(pfcp_update_far_t),
      .mandatory = BIT(UPDATE_FAR_FAR_ID),
      .size = ARRAY_LEN(pfcp_update_far_group),
      .group = pfcp_update_far_group,
    },
    [PFCP_IE_UPDATE_FORWARDING_PARAMETERS] =
    {
      .length = sizeof(pfcp_update_forwarding_parameters_t),
      .mandatory = BIT(0),
      .size = ARRAY_LEN(pfcp_update_forwarding_parameters_group),
      .group = pfcp_update_forwarding_parameters_group,
    },
    [PFCP_IE_UPDATE_BAR_RESPONSE] =
    {
      .length = sizeof(pfcp_update_bar_response_t),
      .mandatory = BIT(UPDATE_BAR_RESPONSE_BAR_ID),
      .size = ARRAY_LEN(pfcp_update_bar_response_group),
      .group = pfcp_update_bar_response_group,
    },
    [PFCP_IE_UPDATE_URR] =
    {
      .length = sizeof(pfcp_update_urr_t),
      .mandatory = BIT(UPDATE_URR_URR_ID),
      .size = ARRAY_LEN(pfcp_update_urr_group),
      .group = pfcp_update_urr_group,
    },
    [PFCP_IE_UPDATE_QER] =
    {
      .length = sizeof(pfcp_update_qer_t),
      .mandatory = BIT(UPDATE_QER_QER_ID),
      .size = ARRAY_LEN(pfcp_update_qer_group),
      .group = pfcp_update_qer_group,
    },
    [PFCP_IE_REMOVE_PDR] =
    {
      .length = sizeof(pfcp_remove_pdr_t),
      .mandatory = BIT(REMOVE_PDR_PDR_ID),
      .size = ARRAY_LEN(pfcp_remove_pdr_group),
      .group = pfcp_remove_pdr_group,
    },
    [PFCP_IE_REMOVE_FAR] =
    {
      .length = sizeof(pfcp_remove_far_t),
      .mandatory = BIT(REMOVE_FAR_FAR_ID),
      .size = ARRAY_LEN(pfcp_remove_far_group),
      .group = pfcp_remove_far_group,
    },
    [PFCP_IE_REMOVE_URR] =
    {
      .length = sizeof(pfcp_remove_urr_t),
      .mandatory = BIT(REMOVE_URR_URR_ID),
      .size = ARRAY_LEN(pfcp_remove_urr_group),
      .group = pfcp_remove_urr_group,
    },
    [PFCP_IE_REMOVE_QER] =
    {
      .length = sizeof(pfcp_remove_qer_t),
      .mandatory = BIT(REMOVE_QER_QER_ID),
      .size = ARRAY_LEN(pfcp_remove_qer_group),
      .group = pfcp_remove_qer_group,
    },
    SIMPLE_IE(PFCP_IE_CAUSE, cause),
    SIMPLE_IE(PFCP_IE_SOURCE_INTERFACE, source_interface),
    SIMPLE_IE(PFCP_IE_F_TEID, f_teid),
    SIMPLE_IE_FREE(PFCP_IE_NETWORK_INSTANCE, network_instance),
    SIMPLE_IE_FREE(PFCP_IE_SDF_FILTER, sdf_filter),
    SIMPLE_IE(PFCP_IE_APPLICATION_ID, application_id),
    SIMPLE_IE(PFCP_IE_GATE_STATUS, gate_status),
    SIMPLE_IE(PFCP_IE_MBR, mbr),
    SIMPLE_IE(PFCP_IE_GBR, gbr),
    SIMPLE_IE(PFCP_IE_QER_CORRELATION_ID, qer_correlation_id),
    SIMPLE_IE(PFCP_IE_PRECEDENCE, precedence),
    SIMPLE_IE(PFCP_IE_TRANSPORT_LEVEL_MARKING, transport_level_marking),
    SIMPLE_IE(PFCP_IE_VOLUME_THRESHOLD, volume_threshold),
    SIMPLE_IE(PFCP_IE_TIME_THRESHOLD, time_threshold),
    SIMPLE_IE(PFCP_IE_MONITORING_TIME, monitoring_time),
    SIMPLE_IE(PFCP_IE_SUBSEQUENT_VOLUME_THRESHOLD, subsequent_volume_threshold),
    SIMPLE_IE(PFCP_IE_SUBSEQUENT_TIME_THRESHOLD, subsequent_time_threshold),
    SIMPLE_IE(PFCP_IE_INACTIVITY_DETECTION_TIME, inactivity_detection_time),
    SIMPLE_IE(PFCP_IE_REPORTING_TRIGGERS, reporting_triggers),
    SIMPLE_IE(PFCP_IE_REDIRECT_INFORMATION, redirect_information),
    SIMPLE_IE(PFCP_IE_REPORT_TYPE, report_type),
    SIMPLE_IE(PFCP_IE_OFFENDING_IE, offending_ie),
    SIMPLE_IE(PFCP_IE_FORWARDING_POLICY, forwarding_policy),
    SIMPLE_IE(PFCP_IE_DESTINATION_INTERFACE, destination_interface),
    SIMPLE_IE(PFCP_IE_UP_FUNCTION_FEATURES, up_function_features),
    SIMPLE_IE(PFCP_IE_APPLY_ACTION, apply_action),
    SIMPLE_IE(PFCP_IE_DOWNLINK_DATA_SERVICE_INFORMATION, downlink_data_service_information),
    SIMPLE_IE(PFCP_IE_DOWNLINK_DATA_NOTIFICATION_DELAY, downlink_data_notification_delay),
    SIMPLE_IE(PFCP_IE_DL_BUFFERING_DURATION, dl_buffering_duration),
    SIMPLE_IE(PFCP_IE_DL_BUFFERING_SUGGESTED_PACKET_COUNT, dl_buffering_suggested_packet_count),
    SIMPLE_IE(PFCP_IE_SXSMREQ_FLAGS, sxsmreq_flags),
    SIMPLE_IE(PFCP_IE_SXSRRSP_FLAGS, sxsrrsp_flags),
    [PFCP_IE_LOAD_CONTROL_INFORMATION] =
    {
      .length = sizeof(pfcp_load_control_information_t),
      .mandatory = (BIT(LOAD_CONTROL_INFORMATION_SEQUENCE_NUMBER) |
		    BIT(LOAD_CONTROL_INFORMATION_METRIC)),
      .size = ARRAY_LEN(pfcp_load_control_information_group),
      .group = pfcp_load_control_information_group,
    },
    SIMPLE_IE(PFCP_IE_SEQUENCE_NUMBER, sequence_number),
    SIMPLE_IE(PFCP_IE_METRIC, metric),
    [PFCP_IE_OVERLOAD_CONTROL_INFORMATION] =
    {
      .length = sizeof(pfcp_overload_control_information_t),
      .mandatory = (BIT(OVERLOAD_CONTROL_INFORMATION_SEQUENCE_NUMBER) |
		    BIT(OVERLOAD_CONTROL_INFORMATION_METRIC) |
		    BIT(OVERLOAD_CONTROL_INFORMATION_TIMER)),
      .size = ARRAY_LEN(pfcp_overload_control_information_group),
      .group = pfcp_overload_control_information_group,
    },
    SIMPLE_IE(PFCP_IE_TIMER, timer),
    SIMPLE_IE(PFCP_IE_PDR_ID, pdr_id),
    SIMPLE_IE(PFCP_IE_F_SEID, f_seid),
    [PFCP_IE_APPLICATION_ID_PFDS] =
    {
      .length = sizeof(pfcp_application_id_pfds_t),
      .mandatory = BIT(APPLICATION_ID_PFDS_APPLICATION_ID),
      .size = ARRAY_LEN(pfcp_application_id_pfds_group),
      .group = pfcp_application_id_pfds_group,
    },
    [PFCP_IE_PFD] =
    {
      .length = sizeof(pfcp_pfd_t),
      .mandatory = BIT(PFD_PFD_CONTENTS),
      .size = ARRAY_LEN(pfcp_pfd_group),
      .group = pfcp_pfd_group,
    },
    SIMPLE_IE_FREE(PFCP_IE_NODE_ID, node_id),
    SIMPLE_IE(PFCP_IE_PFD_CONTENTS, pfd_contents),
    SIMPLE_IE(PFCP_IE_MEASUREMENT_METHOD, measurement_method),
    SIMPLE_IE(PFCP_IE_USAGE_REPORT_TRIGGER, usage_report_trigger),
    SIMPLE_IE(PFCP_IE_MEASUREMENT_PERIOD, measurement_period),
    SIMPLE_IE(PFCP_IE_FQ_CSID, fq_csid),
    SIMPLE_IE(PFCP_IE_VOLUME_MEASUREMENT, volume_measurement),
    SIMPLE_IE(PFCP_IE_DURATION_MEASUREMENT, duration_measurement),
    [PFCP_IE_APPLICATION_DETECTION_INFORMATION] =
    {
      .length = sizeof(pfcp_application_detection_information_t),
      .mandatory = BIT(APPLICATION_DETECTION_INFORMATION_APPLICATION_ID),
      .size = ARRAY_LEN(pfcp_application_detection_information_group),
      .group = pfcp_application_detection_information_group,
    },
    SIMPLE_IE(PFCP_IE_TIME_OF_FIRST_PACKET, time_of_first_packet),
    SIMPLE_IE(PFCP_IE_TIME_OF_LAST_PACKET, time_of_last_packet),
    SIMPLE_IE(PFCP_IE_QUOTA_HOLDING_TIME, quota_holding_time),
    SIMPLE_IE(PFCP_IE_DROPPED_DL_TRAFFIC_THRESHOLD, dropped_dl_traffic_threshold),
    SIMPLE_IE(PFCP_IE_VOLUME_QUOTA, volume_quota),
    SIMPLE_IE(PFCP_IE_TIME_QUOTA, time_quota),
    SIMPLE_IE(PFCP_IE_START_TIME, start_time),
    SIMPLE_IE(PFCP_IE_END_TIME, end_time),
    [PFCP_IE_QUERY_URR] =
    {
      .length = sizeof(pfcp_query_urr_t),
      .mandatory = BIT(QUERY_URR_URR_ID),
      .size = ARRAY_LEN(pfcp_query_urr_group),
      .group = pfcp_query_urr_group,
    },
    [PFCP_IE_USAGE_REPORT_SMR] =
    {
      .length = sizeof(pfcp_usage_report_t),
      .mandatory = (BIT(USAGE_REPORT_URR_ID) |
		    BIT(USAGE_REPORT_UR_SEQN) |
		    BIT(USAGE_REPORT_USAGE_REPORT_TRIGGER)),
      .size = ARRAY_LEN(pfcp_usage_report_smr_group),
      .group = pfcp_usage_report_smr_group,
    },
    [PFCP_IE_USAGE_REPORT_SDR] =
    {
      .length = sizeof(pfcp_usage_report_t),
      .mandatory = (BIT(USAGE_REPORT_URR_ID) |
		    BIT(USAGE_REPORT_UR_SEQN) |
		    BIT(USAGE_REPORT_USAGE_REPORT_TRIGGER)),
      .size = ARRAY_LEN(pfcp_usage_report_sdr_group),
      .group = pfcp_usage_report_sdr_group,
    },
    [PFCP_IE_USAGE_REPORT_SRR] =
    {
      .length = sizeof(pfcp_usage_report_t),
      .mandatory = (BIT(USAGE_REPORT_URR_ID) |
		    BIT(USAGE_REPORT_UR_SEQN) |
		    BIT(USAGE_REPORT_USAGE_REPORT_TRIGGER)),
      .size = ARRAY_LEN(pfcp_usage_report_srr_group),
      .group = pfcp_usage_report_srr_group,
    },
    SIMPLE_IE(PFCP_IE_URR_ID, urr_id),
    SIMPLE_IE(PFCP_IE_LINKED_URR_ID, linked_urr_id),
    [PFCP_IE_DOWNLINK_DATA_REPORT] =
    {
      .length = sizeof(pfcp_downlink_data_report_t),
      .mandatory = BIT(DOWNLINK_DATA_REPORT_PDR_ID),
      .size = ARRAY_LEN(pfcp_downlink_data_report_group),
      .group = pfcp_downlink_data_report_group,
    },
    SIMPLE_IE(PFCP_IE_OUTER_HEADER_CREATION, outer_header_creation),
    [PFCP_IE_CREATE_BAR] =
    {
      .length = sizeof(pfcp_create_bar_t),
      .mandatory = BIT(CREATE_BAR_BAR_ID),
      .size = ARRAY_LEN(pfcp_create_bar_group),
      .group = pfcp_create_bar_group,
    },
    [PFCP_IE_UPDATE_BAR_REQUEST] =
    {
      .length = sizeof(pfcp_update_bar_request_t),
      .mandatory = BIT(UPDATE_BAR_REQUEST_BAR_ID),
      .size = ARRAY_LEN(pfcp_update_bar_request_group),
      .group = pfcp_update_bar_request_group,
    },
    [PFCP_IE_REMOVE_BAR] =
    {
      .length = sizeof(pfcp_remove_bar_t),
      .mandatory = BIT(REMOVE_BAR_BAR_ID),
      .size = ARRAY_LEN(pfcp_remove_bar_group),
      .group = pfcp_remove_bar_group,
    },
    SIMPLE_IE(PFCP_IE_BAR_ID, bar_id),
    SIMPLE_IE(PFCP_IE_CP_FUNCTION_FEATURES, cp_function_features),
    SIMPLE_IE(PFCP_IE_USAGE_INFORMATION, usage_information),
    SIMPLE_IE(PFCP_IE_APPLICATION_INSTANCE_ID, application_instance_id),
    SIMPLE_IE(PFCP_IE_FLOW_INFORMATION, flow_information),
    SIMPLE_IE(PFCP_IE_UE_IP_ADDRESS, ue_ip_address),
    SIMPLE_IE(PFCP_IE_PACKET_RATE, packet_rate),
    SIMPLE_IE(PFCP_IE_OUTER_HEADER_REMOVAL, outer_header_removal),
    SIMPLE_IE(PFCP_IE_RECOVERY_TIME_STAMP, recovery_time_stamp),
    SIMPLE_IE(PFCP_IE_DL_FLOW_LEVEL_MARKING, dl_flow_level_marking),
    SIMPLE_IE(PFCP_IE_HEADER_ENRICHMENT, header_enrichment),
    [PFCP_IE_ERROR_INDICATION_REPORT] =
    {
      .length = sizeof(pfcp_error_indication_report_t),
      .mandatory = BIT(ERROR_INDICATION_REPORT_F_TEID),
      .size = ARRAY_LEN(pfcp_error_indication_report_group),
      .group = pfcp_error_indication_report_group,
    },
    SIMPLE_IE(PFCP_IE_MEASUREMENT_INFORMATION, measurement_information),
    SIMPLE_IE(PFCP_IE_NODE_REPORT_TYPE, node_report_type),
    [PFCP_IE_USER_PLANE_PATH_FAILURE_REPORT] =
    {
      .length = sizeof(pfcp_user_plane_path_failure_report_t),
      .mandatory = BIT(USER_PLANE_PATH_FAILURE_REPORT_REMOTE_GTP_U_PEER),
      .size = ARRAY_LEN(pfcp_user_plane_path_failure_report_group),
      .group = pfcp_user_plane_path_failure_report_group,
    },
    SIMPLE_IE(PFCP_IE_REMOTE_GTP_U_PEER, remote_gtp_u_peer),
    SIMPLE_IE(PFCP_IE_UR_SEQN, ur_seqn),
    [PFCP_IE_UPDATE_DUPLICATING_PARAMETERS] =
    {
      .length = sizeof(pfcp_update_duplicating_parameters_t),
      .mandatory = BIT(0),
      .size = ARRAY_LEN(pfcp_update_duplicating_parameters_group),
      .group = pfcp_update_duplicating_parameters_group,
    },
    SIMPLE_IE(PFCP_IE_ACTIVATE_PREDEFINED_RULES, activate_predefined_rules),
    SIMPLE_IE(PFCP_IE_DEACTIVATE_PREDEFINED_RULES, deactivate_predefined_rules),
    SIMPLE_IE(PFCP_IE_FAR_ID, far_id),
    SIMPLE_IE(PFCP_IE_QER_ID, qer_id),
    SIMPLE_IE(PFCP_IE_OCI_FLAGS, oci_flags),
    SIMPLE_IE(PFCP_IE_SX_ASSOCIATION_RELEASE_REQUEST, sx_association_release_request),
    SIMPLE_IE(PFCP_IE_GRACEFUL_RELEASE_PERIOD, graceful_release_period),
    SIMPLE_IE(PFCP_IE_PDN_TYPE, pdn_type),
    SIMPLE_IE(PFCP_IE_FAILED_RULE_ID, failed_rule_id),
    SIMPLE_IE(PFCP_IE_TIME_QUOTA_MECHANISM, time_quota_mechanism),
    SIMPLE_IE_FREE(PFCP_IE_USER_PLANE_IP_RESOURCE_INFORMATION, user_plane_ip_resource_information),
  };

/**********************************************************/



/**********************************************************/


/* PFCP Methods */

static struct pfcp_group_ie_def pfcp_heartbeat_request_group[] =
  {
    [HEARTBEAT_REQUEST_RECOVERY_TIME_STAMP] = {
      .type = PFCP_IE_RECOVERY_TIME_STAMP,
      .offset = offsetof(pfcp_heartbeat_request_t, recovery_time_stamp)
    },
  };

static struct pfcp_group_ie_def pfcp_heartbeat_response_group[] =
  {
    [HEARTBEAT_RESPONSE_RECOVERY_TIME_STAMP] = {
      .type = PFCP_IE_RECOVERY_TIME_STAMP,
      .offset = offsetof(pfcp_heartbeat_response_t, recovery_time_stamp)
    },
  };

static struct pfcp_group_ie_def pfcp_pfd_management_request_group[] =
  {
    [PFD_MANAGEMENT_REQUEST_APPLICATION_ID_PFDS] = {
      .type = PFCP_IE_APPLICATION_ID_PFDS,
      .is_array = true,
      .offset = offsetof(pfcp_pfd_management_request_t, application_id_pfds)
    },
  };

static struct pfcp_group_ie_def pfcp_pfd_management_response_group[] =
  {
    [PFD_MANAGEMENT_RESPONSE_CAUSE] = {
      .type = PFCP_IE_CAUSE,
      .offset = offsetof(pfcp_pfd_management_response_t, response.cause)
    },
    [PFD_MANAGEMENT_RESPONSE_OFFENDING_IE] = {
      .type = PFCP_IE_OFFENDING_IE,
      .offset = offsetof(pfcp_pfd_management_response_t, response.offending_ie)
    },
  };

static struct pfcp_group_ie_def pfcp_association_setup_request_group[] =
  {
    [ASSOCIATION_SETUP_REQUEST_NODE_ID] = {
      .type = PFCP_IE_NODE_ID,
      .offset = offsetof(pfcp_association_setup_request_t, request.node_id)
    },
    [ASSOCIATION_SETUP_REQUEST_RECOVERY_TIME_STAMP] = {
      .type = PFCP_IE_RECOVERY_TIME_STAMP,
      .offset = offsetof(pfcp_association_setup_request_t, recovery_time_stamp)
    },
    [ASSOCIATION_SETUP_REQUEST_CP_FUNCTION_FEATURES] = {
      .type = PFCP_IE_CP_FUNCTION_FEATURES,
      .offset = offsetof(pfcp_association_setup_request_t, cp_function_features)
    },
    [ASSOCIATION_SETUP_REQUEST_UP_FUNCTION_FEATURES] = {
      .type = PFCP_IE_UP_FUNCTION_FEATURES,
      .offset = offsetof(pfcp_association_setup_request_t, up_function_features)
    },
    [ASSOCIATION_SETUP_REQUEST_USER_PLANE_IP_RESOURCE_INFORMATION] = {
      .type = PFCP_IE_USER_PLANE_IP_RESOURCE_INFORMATION,
      .is_array = true,
      .offset = offsetof(pfcp_association_setup_request_t, user_plane_ip_resource_information)
    },
  };

static struct pfcp_group_ie_def pfcp_association_setup_response_group[] =
  {
    [ASSOCIATION_SETUP_RESPONSE_NODE_ID] = {
      .type = PFCP_IE_NODE_ID,
      .offset = offsetof(pfcp_association_setup_response_t, response.node_id)
    },
    [ASSOCIATION_SETUP_RESPONSE_CAUSE] = {
      .type = PFCP_IE_CAUSE,
      .offset = offsetof(pfcp_association_setup_response_t, response.cause)
    },
    [ASSOCIATION_SETUP_RESPONSE_RECOVERY_TIME_STAMP] = {
      .type = PFCP_IE_RECOVERY_TIME_STAMP,
      .offset = offsetof(pfcp_association_setup_response_t, recovery_time_stamp)
    },
    [ASSOCIATION_SETUP_RESPONSE_CP_FUNCTION_FEATURES] = {
      .type = PFCP_IE_CP_FUNCTION_FEATURES,
      .offset = offsetof(pfcp_association_setup_response_t, cp_function_features)
    },
    [ASSOCIATION_SETUP_RESPONSE_UP_FUNCTION_FEATURES] = {
      .type = PFCP_IE_UP_FUNCTION_FEATURES,
      .offset = offsetof(pfcp_association_setup_response_t, up_function_features)
    },
    [ASSOCIATION_SETUP_RESPONSE_USER_PLANE_IP_RESOURCE_INFORMATION] = {
      .type = PFCP_IE_USER_PLANE_IP_RESOURCE_INFORMATION,
      .is_array = true,
      .offset = offsetof(pfcp_association_setup_response_t, user_plane_ip_resource_information)
    },
  };

static struct pfcp_group_ie_def pfcp_association_update_request_group[] =
  {
    [ASSOCIATION_UPDATE_REQUEST_NODE_ID] = {
      .type = PFCP_IE_NODE_ID,
      .offset = offsetof(pfcp_association_update_request_t, request.node_id)
    },
    [ASSOCIATION_UPDATE_REQUEST_CP_FUNCTION_FEATURES] = {
      .type = PFCP_IE_CP_FUNCTION_FEATURES,
      .offset = offsetof(pfcp_association_update_request_t, cp_function_features)
    },
    [ASSOCIATION_UPDATE_REQUEST_UP_FUNCTION_FEATURES] = {
      .type = PFCP_IE_UP_FUNCTION_FEATURES,
      .offset = offsetof(pfcp_association_update_request_t, up_function_features)
    },
    [ASSOCIATION_UPDATE_REQUEST_SX_ASSOCIATION_RELEASE_REQUEST] = {
      .type = PFCP_IE_SX_ASSOCIATION_RELEASE_REQUEST,
      .offset = offsetof(pfcp_association_update_request_t, sx_association_release_request)
    },
    [ASSOCIATION_UPDATE_REQUEST_GRACEFUL_RELEASE_PERIOD] = {
      .type = PFCP_IE_GRACEFUL_RELEASE_PERIOD,
      .offset = offsetof(pfcp_association_update_request_t, graceful_release_period)
    },
    [ASSOCIATION_UPDATE_REQUEST_USER_PLANE_IP_RESOURCE_INFORMATION] = {
      .type = PFCP_IE_USER_PLANE_IP_RESOURCE_INFORMATION,
      .is_array = true,
      .offset = offsetof(pfcp_association_update_request_t, user_plane_ip_resource_information)
    },
  };

static struct pfcp_group_ie_def pfcp_association_update_response_group[] =
  {
    [ASSOCIATION_UPDATE_RESPONSE_NODE_ID] = {
      .type = PFCP_IE_NODE_ID,
      .offset = offsetof(pfcp_association_update_response_t, response.node_id)
    },
    [ASSOCIATION_UPDATE_RESPONSE_CAUSE] = {
      .type = PFCP_IE_CAUSE,
      .offset = offsetof(pfcp_association_update_response_t, response.cause)
    },
    [ASSOCIATION_UPDATE_RESPONSE_CP_FUNCTION_FEATURES] = {
      .type = PFCP_IE_CP_FUNCTION_FEATURES,
      .offset = offsetof(pfcp_association_update_response_t, cp_function_features)
    },
    [ASSOCIATION_UPDATE_RESPONSE_UP_FUNCTION_FEATURES] = {
      .type = PFCP_IE_UP_FUNCTION_FEATURES,
      .offset = offsetof(pfcp_association_update_response_t, up_function_features)
    },
  };

static struct pfcp_group_ie_def pfcp_association_release_request_group[] =
  {
    [ASSOCIATION_RELEASE_REQUEST_NODE_ID] = {
      .type = PFCP_IE_NODE_ID,
      .offset = offsetof(pfcp_association_release_request_t, request.node_id)
    },
  };

static struct pfcp_group_ie_def pfcp_association_release_response_group[] =
  {
    [ASSOCIATION_RELEASE_RESPONSE_NODE_ID] = {
      .type = PFCP_IE_NODE_ID,
      .offset = offsetof(pfcp_association_release_response_t, response.node_id)
    },
    [ASSOCIATION_RELEASE_RESPONSE_CAUSE] = {
      .type = PFCP_IE_CAUSE,
      .offset = offsetof(pfcp_association_release_response_t, response.cause)
    },
  };

static struct pfcp_group_ie_def pfcp_node_report_request_group[] =
  {
    [NODE_REPORT_REQUEST_NODE_ID] = {
      .type = PFCP_IE_NODE_ID,
      .offset = offsetof(pfcp_node_report_request_t, request.node_id)
    },
    [NODE_REPORT_REQUEST_NODE_REPORT_TYPE] = {
      .type = PFCP_IE_NODE_REPORT_TYPE,
      .offset = offsetof(pfcp_node_report_request_t, node_report_type)
    },
    [NODE_REPORT_REQUEST_USER_PLANE_PATH_FAILURE_REPORT] = {
      .type = PFCP_IE_USER_PLANE_PATH_FAILURE_REPORT,
      .offset = offsetof(pfcp_node_report_request_t, user_plane_path_failure_report)
    },
  };

static struct pfcp_group_ie_def pfcp_node_report_response_group[] =
  {
    [NODE_REPORT_RESPONSE_NODE_ID] = {
      .type = PFCP_IE_NODE_ID,
      .offset = offsetof(pfcp_node_report_response_t, response.node_id)
    },
    [NODE_REPORT_RESPONSE_CAUSE] = {
      .type = PFCP_IE_CAUSE,
      .offset = offsetof(pfcp_node_report_response_t, response.cause)
    },
    [NODE_REPORT_RESPONSE_OFFENDING_IE] = {
      .type = PFCP_IE_OFFENDING_IE,
      .offset = offsetof(pfcp_node_report_response_t, response.offending_ie)
    },
  };

static struct pfcp_group_ie_def pfcp_session_set_deletion_request_group[] =
  {
    [SESSION_SET_DELETION_REQUEST_NODE_ID] = {
      .type = PFCP_IE_NODE_ID,
      .offset = offsetof(pfcp_session_set_deletion_request_t, request.node_id)
    },
    [SESSION_SET_DELETION_REQUEST_FQ_CSID] = {
      .type = PFCP_IE_FQ_CSID,
      .is_array = true,
      .offset = offsetof(pfcp_session_set_deletion_request_t, fq_csid)
    },
  };

static struct pfcp_group_ie_def pfcp_session_set_deletion_response_group[] =
  {
    [SESSION_SET_DELETION_RESPONSE_NODE_ID] = {
      .type = PFCP_IE_NODE_ID,
      .offset = offsetof(pfcp_session_set_deletion_response_t, response.node_id)
    },
    [SESSION_SET_DELETION_RESPONSE_CAUSE] = {
      .type = PFCP_IE_CAUSE,
      .offset = offsetof(pfcp_session_set_deletion_response_t, response.cause)
    },
    [SESSION_SET_DELETION_RESPONSE_OFFENDING_IE] = {
      .type = PFCP_IE_OFFENDING_IE,
      .offset = offsetof(pfcp_session_set_deletion_response_t, response.offending_ie)
    },
  };

static struct pfcp_group_ie_def pfcp_session_establishment_request_group[] =
  {
    [SESSION_ESTABLISHMENT_REQUEST_NODE_ID] = {
      .type = PFCP_IE_NODE_ID,
      .offset = offsetof(pfcp_session_establishment_request_t, request.node_id)
    },
    [SESSION_ESTABLISHMENT_REQUEST_F_SEID] = {
      .type = PFCP_IE_F_SEID,
      .offset = offsetof(pfcp_session_establishment_request_t, f_seid)
    },
    [SESSION_ESTABLISHMENT_REQUEST_CREATE_PDR] = {
      .type = PFCP_IE_CREATE_PDR,
      .is_array = true,
      .offset = offsetof(pfcp_session_establishment_request_t, create_pdr)
    },
    [SESSION_ESTABLISHMENT_REQUEST_CREATE_FAR] = {
      .type = PFCP_IE_CREATE_FAR,
      .is_array = true,
      .offset = offsetof(pfcp_session_establishment_request_t, create_far)
    },
    [SESSION_ESTABLISHMENT_REQUEST_CREATE_URR] = {
      .type = PFCP_IE_CREATE_URR,
      .is_array = true,
      .offset = offsetof(pfcp_session_establishment_request_t, create_urr)
    },
    [SESSION_ESTABLISHMENT_REQUEST_CREATE_QER] = {
      .type = PFCP_IE_CREATE_QER,
      .is_array = true,
      .offset = offsetof(pfcp_session_establishment_request_t, create_qer)
    },
    [SESSION_ESTABLISHMENT_REQUEST_CREATE_BAR] = {
      .type = PFCP_IE_CREATE_BAR,
      .is_array = true,
      .offset = offsetof(pfcp_session_establishment_request_t, create_bar)
    },
    [SESSION_ESTABLISHMENT_REQUEST_PDN_TYPE] = {
      .type = PFCP_IE_PDN_TYPE,
      .offset = offsetof(pfcp_session_establishment_request_t, pdn_type)
    },
    [SESSION_ESTABLISHMENT_REQUEST_FQ_CSID] = {
      .type = PFCP_IE_FQ_CSID,
      .is_array = true,
      .offset = offsetof(pfcp_session_establishment_request_t, fq_csid)
    },
  };

static struct pfcp_group_ie_def pfcp_session_establishment_response_group[] =
  {
    [SESSION_ESTABLISHMENT_RESPONSE_NODE_ID] = {
      .type = PFCP_IE_NODE_ID,
      .offset = offsetof(pfcp_session_establishment_response_t, response.node_id)
    },
    [SESSION_ESTABLISHMENT_RESPONSE_CAUSE] = {
      .type = PFCP_IE_CAUSE,
      .offset = offsetof(pfcp_session_establishment_response_t, response.cause)
    },
    [SESSION_ESTABLISHMENT_RESPONSE_OFFENDING_IE] = {
      .type = PFCP_IE_OFFENDING_IE,
      .offset = offsetof(pfcp_session_establishment_response_t, response.offending_ie)
    },
    [SESSION_ESTABLISHMENT_RESPONSE_UP_F_SEID] = {
      .type = PFCP_IE_F_SEID,
      .offset = offsetof(pfcp_session_establishment_response_t, up_f_seid)
    },
    [SESSION_ESTABLISHMENT_RESPONSE_CREATED_PDR] = {
      .type = PFCP_IE_CREATED_PDR,
      .is_array = true,
      .offset = offsetof(pfcp_session_establishment_response_t, created_pdr)
    },
    [SESSION_ESTABLISHMENT_RESPONSE_LOAD_CONTROL_INFORMATION] = {
      .type = PFCP_IE_LOAD_CONTROL_INFORMATION,
      .offset = offsetof(pfcp_session_establishment_response_t, load_control_information)
    },
    [SESSION_ESTABLISHMENT_RESPONSE_OVERLOAD_CONTROL_INFORMATION] = {
      .type = PFCP_IE_OVERLOAD_CONTROL_INFORMATION,
      .offset = offsetof(pfcp_session_establishment_response_t, overload_control_information)
    },
    [SESSION_ESTABLISHMENT_RESPONSE_FQ_CSID] = {
      .type = PFCP_IE_FQ_CSID,
      .is_array = true,
      .offset = offsetof(pfcp_session_establishment_response_t, fq_csid)
    },
    [SESSION_ESTABLISHMENT_RESPONSE_FAILED_RULE_ID] = {
      .type = PFCP_IE_FAILED_RULE_ID,
      .offset = offsetof(pfcp_session_establishment_response_t, failed_rule_id)
    },
  };

static struct pfcp_group_ie_def pfcp_session_modification_request_group[] =
  {
    [SESSION_MODIFICATION_REQUEST_F_SEID] = {
      .type = PFCP_IE_F_SEID,
      .offset = offsetof(pfcp_session_modification_request_t, f_seid)
    },
    [SESSION_MODIFICATION_REQUEST_REMOVE_PDR] = {
      .type = PFCP_IE_REMOVE_PDR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, remove_pdr)
    },
    [SESSION_MODIFICATION_REQUEST_REMOVE_FAR] = {
      .type = PFCP_IE_REMOVE_FAR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, remove_far)
    },
    [SESSION_MODIFICATION_REQUEST_REMOVE_URR] = {
      .type = PFCP_IE_REMOVE_URR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, remove_urr)
    },
    [SESSION_MODIFICATION_REQUEST_REMOVE_QER] = {
      .type = PFCP_IE_REMOVE_QER,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, remove_qer)
    },
    [SESSION_MODIFICATION_REQUEST_REMOVE_BAR] = {
      .type = PFCP_IE_REMOVE_BAR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, remove_bar)
    },
    [SESSION_MODIFICATION_REQUEST_CREATE_PDR] = {
      .type = PFCP_IE_CREATE_PDR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, create_pdr)
    },
    [SESSION_MODIFICATION_REQUEST_CREATE_FAR] = {
      .type = PFCP_IE_CREATE_FAR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, create_far)
    },
    [SESSION_MODIFICATION_REQUEST_CREATE_URR] = {
      .type = PFCP_IE_CREATE_URR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, create_urr)
    },
    [SESSION_MODIFICATION_REQUEST_CREATE_QER] = {
      .type = PFCP_IE_CREATE_QER,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, create_qer)
    },
    [SESSION_MODIFICATION_REQUEST_CREATE_BAR] = {
      .type = PFCP_IE_CREATE_BAR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, create_bar)
    },
    [SESSION_MODIFICATION_REQUEST_UPDATE_PDR] = {
      .type = PFCP_IE_UPDATE_PDR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, update_pdr)
    },
    [SESSION_MODIFICATION_REQUEST_UPDATE_FAR] = {
      .type = PFCP_IE_UPDATE_FAR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, update_far)
    },
    [SESSION_MODIFICATION_REQUEST_UPDATE_URR] = {
      .type = PFCP_IE_UPDATE_URR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, update_urr)
    },
    [SESSION_MODIFICATION_REQUEST_UPDATE_QER] = {
      .type = PFCP_IE_UPDATE_QER,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, update_qer)
    },
    [SESSION_MODIFICATION_REQUEST_UPDATE_BAR] = {
      .type = PFCP_IE_UPDATE_BAR_REQUEST,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, update_bar)
    },
    [SESSION_MODIFICATION_REQUEST_SXSMREQ_FLAGS] = {
      .type = PFCP_IE_SXSMREQ_FLAGS,
      .offset = offsetof(pfcp_session_modification_request_t, sxsmreq_flags)
    },
    [SESSION_MODIFICATION_REQUEST_QUERY_URR] = {
      .type = PFCP_IE_QUERY_URR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, query_urr)
    },
    [SESSION_MODIFICATION_REQUEST_FQ_CSID] = {
      .type = PFCP_IE_FQ_CSID,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_request_t, fq_csid)
    },
  };

static struct pfcp_group_ie_def pfcp_session_modification_response_group[] =
  {
    [SESSION_MODIFICATION_RESPONSE_CAUSE] = {
      .type = PFCP_IE_CAUSE,
      .offset = offsetof(pfcp_session_modification_response_t, response.cause)
    },
    [SESSION_MODIFICATION_RESPONSE_OFFENDING_IE] = {
      .type = PFCP_IE_OFFENDING_IE,
      .offset = offsetof(pfcp_session_modification_response_t, response.offending_ie)
    },
    [SESSION_MODIFICATION_RESPONSE_CREATED_PDR] = {
      .type = PFCP_IE_CREATED_PDR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_response_t, created_pdr)
    },
    [SESSION_MODIFICATION_RESPONSE_LOAD_CONTROL_INFORMATION] = {
      .type = PFCP_IE_LOAD_CONTROL_INFORMATION,
      .offset = offsetof(pfcp_session_modification_response_t, load_control_information)
    },
    [SESSION_MODIFICATION_RESPONSE_OVERLOAD_CONTROL_INFORMATION] = {
      .type = PFCP_IE_OVERLOAD_CONTROL_INFORMATION,
      .offset = offsetof(pfcp_session_modification_response_t, overload_control_information)
    },
    [SESSION_MODIFICATION_RESPONSE_USAGE_REPORT] = {
      .type = PFCP_IE_USAGE_REPORT_SMR,
      .is_array = true,
      .offset = offsetof(pfcp_session_modification_response_t, usage_report)
    },
    [SESSION_MODIFICATION_RESPONSE_FAILED_RULE_ID] = {
      .type = PFCP_IE_FAILED_RULE_ID,
      .offset = offsetof(pfcp_session_modification_response_t, failed_rule_id)
    },
  };

static struct pfcp_group_ie_def pfcp_session_deletion_response_group[] =
  {
    [SESSION_DELETION_RESPONSE_CAUSE] = {
      .type = PFCP_IE_CAUSE,
      .offset = offsetof(pfcp_session_deletion_response_t, response.cause)
    },
    [SESSION_DELETION_RESPONSE_OFFENDING_IE] = {
      .type = PFCP_IE_OFFENDING_IE,
      .offset = offsetof(pfcp_session_deletion_response_t, response.offending_ie)
    },
    [SESSION_DELETION_RESPONSE_LOAD_CONTROL_INFORMATION] = {
      .type = PFCP_IE_LOAD_CONTROL_INFORMATION,
      .offset = offsetof(pfcp_session_deletion_response_t, load_control_information)
    },
    [SESSION_DELETION_RESPONSE_OVERLOAD_CONTROL_INFORMATION] = {
      .type = PFCP_IE_OVERLOAD_CONTROL_INFORMATION,
      .offset = offsetof(pfcp_session_deletion_response_t, overload_control_information)
    },
    [SESSION_DELETION_RESPONSE_USAGE_REPORT] = {
      .type = PFCP_IE_USAGE_REPORT_SDR,
      .is_array = true,
      .offset = offsetof(pfcp_session_deletion_response_t, usage_report)
    },
  };

static struct pfcp_group_ie_def pfcp_session_report_request_group[] =
  {
    [SESSION_REPORT_REQUEST_REPORT_TYPE] = {
      .type = PFCP_IE_REPORT_TYPE,
      .offset = offsetof(pfcp_session_report_request_t, report_type)
    },
    [SESSION_REPORT_REQUEST_DOWNLINK_DATA_REPORT] = {
      .type = PFCP_IE_DOWNLINK_DATA_REPORT,
      .offset = offsetof(pfcp_session_report_request_t, downlink_data_report)
    },
    [SESSION_REPORT_REQUEST_USAGE_REPORT] = {
      .type = PFCP_IE_USAGE_REPORT_SRR,
      .is_array = true,
      .offset = offsetof(pfcp_session_report_request_t, usage_report)
    },
    [SESSION_REPORT_REQUEST_ERROR_INDICATION_REPORT] = {
      .type = PFCP_IE_ERROR_INDICATION_REPORT,
      .offset = offsetof(pfcp_session_report_request_t, error_indication_report)
    },
    [SESSION_REPORT_REQUEST_LOAD_CONTROL_INFORMATION] = {
      .type = PFCP_IE_LOAD_CONTROL_INFORMATION,
      .offset = offsetof(pfcp_session_report_request_t, load_control_information)
    },
    [SESSION_REPORT_REQUEST_OVERLOAD_CONTROL_INFORMATION] = {
      .type = PFCP_IE_OVERLOAD_CONTROL_INFORMATION,
      .offset = offsetof(pfcp_session_report_request_t, overload_control_information)
    },
  };

static struct pfcp_group_ie_def pfcp_session_report_response_group[] =
  {
    [SESSION_REPORT_RESPONSE_CAUSE] = {
      .type = PFCP_IE_CAUSE,
      .offset = offsetof(pfcp_session_report_response_t, response.cause)
    },
    [SESSION_REPORT_RESPONSE_OFFENDING_IE] = {
      .type = PFCP_IE_OFFENDING_IE,
      .offset = offsetof(pfcp_session_report_response_t, response.offending_ie)
    },
    [SESSION_REPORT_RESPONSE_UPDATE_BAR] = {
      .type = PFCP_IE_UPDATE_BAR_RESPONSE,
      .is_array = true,
      .offset = offsetof(pfcp_session_report_response_t, update_bar)
    },
    [SESSION_REPORT_RESPONSE_SXSRRSP_FLAGS] = {
      .type = PFCP_IE_SXSRRSP_FLAGS,
      .offset = offsetof(pfcp_session_report_response_t, sxsrrsp_flags)
    },
  };

static struct pfcp_ie_def msg_specs[] =
  {
    [PFCP_HEARTBEAT_REQUEST] =
    {
      .length = sizeof(pfcp_heartbeat_request_t),
      .mandatory = BIT(HEARTBEAT_REQUEST_RECOVERY_TIME_STAMP),
      .size = ARRAY_LEN(pfcp_heartbeat_request_group),
      .group = pfcp_heartbeat_request_group,
    },

    [PFCP_HEARTBEAT_RESPONSE] =
    {
      .length = sizeof(pfcp_heartbeat_response_t),
      .mandatory = BIT(HEARTBEAT_RESPONSE_RECOVERY_TIME_STAMP),
      .size = ARRAY_LEN(pfcp_heartbeat_response_group),
      .group = pfcp_heartbeat_response_group,
    },

    [PFCP_PFD_MANAGEMENT_REQUEST] =
    {
      .length = sizeof(pfcp_pfd_management_request_t),
      .size = ARRAY_LEN(pfcp_pfd_management_request_group),
      .group = pfcp_pfd_management_request_group,
    },

    [PFCP_PFD_MANAGEMENT_RESPONSE] =
    {
      .length = sizeof(pfcp_pfd_management_response_t),
      .mandatory = BIT(PFD_MANAGEMENT_RESPONSE_CAUSE),
      .size = ARRAY_LEN(pfcp_pfd_management_response_group),
      .group = pfcp_pfd_management_response_group,
    },

    [PFCP_ASSOCIATION_SETUP_REQUEST] =
    {
      .length = sizeof(pfcp_association_setup_request_t),
      .mandatory = (BIT(ASSOCIATION_SETUP_REQUEST_NODE_ID) |
		    BIT(ASSOCIATION_SETUP_REQUEST_RECOVERY_TIME_STAMP)),
      .size = ARRAY_LEN(pfcp_association_setup_request_group),
      .group = pfcp_association_setup_request_group,
    },

    [PFCP_ASSOCIATION_SETUP_RESPONSE] =
    {
      .length = sizeof(pfcp_association_setup_response_t),
      .mandatory = (BIT(ASSOCIATION_SETUP_RESPONSE_NODE_ID) |
		    BIT(ASSOCIATION_SETUP_RESPONSE_CAUSE) |
		    BIT(ASSOCIATION_SETUP_RESPONSE_RECOVERY_TIME_STAMP)),
      .size = ARRAY_LEN(pfcp_association_setup_response_group),
      .group = pfcp_association_setup_response_group,
    },

    [PFCP_ASSOCIATION_UPDATE_REQUEST] =
    {
      .length = sizeof(pfcp_association_update_request_t),
      .mandatory = BIT(ASSOCIATION_UPDATE_REQUEST_NODE_ID),
      .size = ARRAY_LEN(pfcp_association_update_request_group),
      .group = pfcp_association_update_request_group,
    },

    [PFCP_ASSOCIATION_UPDATE_RESPONSE] =
    {
      .length = sizeof(pfcp_association_update_response_t),
      .mandatory = (BIT(ASSOCIATION_UPDATE_RESPONSE_NODE_ID) |
		    BIT(ASSOCIATION_UPDATE_RESPONSE_CAUSE)),
      .size = ARRAY_LEN(pfcp_association_update_response_group),
      .group = pfcp_association_update_response_group,
    },

    [PFCP_ASSOCIATION_RELEASE_REQUEST] =
    {
      .length = sizeof(pfcp_association_release_request_t),
      .mandatory = BIT(ASSOCIATION_RELEASE_REQUEST_NODE_ID),
      .size = ARRAY_LEN(pfcp_association_release_request_group),
      .group = pfcp_association_release_request_group,
    },

    [PFCP_ASSOCIATION_RELEASE_RESPONSE] =
    {
      .length = sizeof(pfcp_association_release_response_t),
      .mandatory = (BIT(ASSOCIATION_RELEASE_RESPONSE_NODE_ID) |
		    BIT(ASSOCIATION_RELEASE_RESPONSE_CAUSE)),
      .size = ARRAY_LEN(pfcp_association_release_response_group),
      .group = pfcp_association_release_response_group,
    },

    [PFCP_NODE_REPORT_REQUEST] =
    {
      .length = sizeof(pfcp_node_report_request_t),
      .mandatory = (BIT(NODE_REPORT_REQUEST_NODE_ID) |
		    BIT(NODE_REPORT_REQUEST_NODE_REPORT_TYPE)),
      .size = ARRAY_LEN(pfcp_node_report_request_group),
      .group = pfcp_node_report_request_group,
    },

    [PFCP_NODE_REPORT_RESPONSE] =
    {
      .length = sizeof(pfcp_node_report_response_t),
      .mandatory = (BIT(NODE_REPORT_RESPONSE_NODE_ID) |
		    BIT(NODE_REPORT_RESPONSE_CAUSE)),
      .size = ARRAY_LEN(pfcp_node_report_response_group),
      .group = pfcp_node_report_response_group,
    },

    [PFCP_SESSION_SET_DELETION_REQUEST] =
    {
      .length = sizeof(pfcp_session_set_deletion_request_t),
      .mandatory = BIT(SESSION_SET_DELETION_REQUEST_NODE_ID),
      .size = ARRAY_LEN(pfcp_session_set_deletion_request_group),
      .group = pfcp_session_set_deletion_request_group,
    },

    [PFCP_SESSION_SET_DELETION_RESPONSE] =
    {
      .length = sizeof(pfcp_session_set_deletion_response_t),
      .mandatory = (BIT(SESSION_SET_DELETION_RESPONSE_NODE_ID) |
		    BIT(SESSION_SET_DELETION_RESPONSE_CAUSE)),
      .size = ARRAY_LEN(pfcp_session_set_deletion_response_group),
      .group = pfcp_session_set_deletion_response_group,
    },


    [PFCP_SESSION_ESTABLISHMENT_REQUEST] =
    {
      .length = sizeof(pfcp_session_establishment_request_t),
      .mandatory = (BIT(SESSION_ESTABLISHMENT_REQUEST_NODE_ID) |
		    BIT(SESSION_ESTABLISHMENT_REQUEST_F_SEID) |
		    BIT(SESSION_ESTABLISHMENT_REQUEST_CREATE_PDR) |
		    BIT(SESSION_ESTABLISHMENT_REQUEST_CREATE_FAR)),
      .size = ARRAY_LEN(pfcp_session_establishment_request_group),
      .group = pfcp_session_establishment_request_group,
    },

    [PFCP_SESSION_ESTABLISHMENT_RESPONSE] =
    {
      .length = sizeof(pfcp_session_establishment_response_t),
      .mandatory = (BIT(SESSION_ESTABLISHMENT_RESPONSE_NODE_ID) |
		    BIT(SESSION_ESTABLISHMENT_RESPONSE_CAUSE) |
		    BIT(SESSION_ESTABLISHMENT_RESPONSE_UP_F_SEID)),
      .size = ARRAY_LEN(pfcp_session_establishment_response_group),
      .group = pfcp_session_establishment_response_group,
    },

    [PFCP_SESSION_MODIFICATION_REQUEST] =

    {
    .length = sizeof(pfcp_session_modification_request_t),
    .size = ARRAY_LEN(pfcp_session_modification_request_group),
    .group = pfcp_session_modification_request_group,

    },

    [PFCP_SESSION_MODIFICATION_RESPONSE] =
    {
      .length = sizeof(pfcp_session_modification_response_t),
      .mandatory = BIT(SESSION_MODIFICATION_RESPONSE_CAUSE),
      .size = ARRAY_LEN(pfcp_session_modification_response_group),
      .group = pfcp_session_modification_response_group,
    },

    [PFCP_SESSION_DELETION_REQUEST] =
    {
      .length = sizeof(pfcp_session_deletion_request_t),
    },

    [PFCP_SESSION_DELETION_RESPONSE] =
    {
      .length = sizeof(pfcp_session_deletion_response_t),
      .mandatory = BIT(SESSION_DELETION_RESPONSE_CAUSE),
      .size = ARRAY_LEN(pfcp_session_deletion_response_group),
      .group = pfcp_session_deletion_response_group,
    },

    [PFCP_SESSION_REPORT_REQUEST] =
    {
      .length = sizeof(pfcp_session_report_request_t),
      .mandatory = BIT(SESSION_REPORT_REQUEST_REPORT_TYPE),
      .size = ARRAY_LEN(pfcp_session_report_request_group),
      .group = pfcp_session_report_request_group,
    },

    [PFCP_SESSION_REPORT_RESPONSE] =
    {
      .length = sizeof(pfcp_session_report_response_t),
      .mandatory = BIT(SESSION_REPORT_RESPONSE_CAUSE),
      .size = ARRAY_LEN(pfcp_session_report_response_group),
      .group = pfcp_session_report_response_group,
    },
  };

static const
struct pfcp_group_ie_def *get_ie_spec(const pfcp_ie_t *ie,
				      const struct pfcp_ie_def *def)
{
  for (int i = 0; i < def->size; i++)
    if (def->group[i].type != 0 &&
	def->group[i].type == ntohs(ie->type))
      return &def->group[i];

  return NULL;
}

static int decode_group(u8 *p, int len, const struct pfcp_ie_def *grp_def,
			struct pfcp_group *grp);

static int decode_ie(const struct pfcp_ie_def *def, u8 *ie, u16 length, void *p)
{
  if (def->size != 0)
      return decode_group(ie, length, def, (struct pfcp_group *)p);
  else
    return def->decode(ie, length, p);
}

static int decode_vector_ie(const struct pfcp_ie_def *def, u8 *ie, u16 length, void *p)
{
  u8 **v = (u8 **)p;
  uword vl;
  int r;

  /*
   * black magic to expand a vector without having know the element type...
   */
  vl = vec_len(*v);
  *v = _vec_resize(*v, 1, (vl + 1) * def->length, 0, 0);
  memset(*v + (vl * def->length), 0, def->length);
  _vec_len(*v) = vl;

  if ((r = decode_ie(def, ie, length, *v + (vl * def->length))) == 0)
    _vec_len(*v)++;

  return r;
}

static int decode_group(u8 *p, int len, const struct pfcp_ie_def *grp_def,
			struct pfcp_group *grp)
{
  int r = 0, pos = 0;

  while (r == 0 && pos < len) {
    pfcp_ie_t *ie = (pfcp_ie_t *)&p[pos];
    u16 length = ntohs(ie->length);
    const struct pfcp_group_ie_def *item;

    pfcp_debug("%U", format_pfcp_ie, ie);

    if (pos + length >= len)
	return PFCP_CAUSE_INVALID_LENGTH;

    item = get_ie_spec(ie, grp_def);

    if (!item)
      {
	vec_add1(grp->ies, ie);
	goto next;
      }

    int id = item - grp_def->group;
    const struct pfcp_ie_def *ie_def = &group_specs[ntohs(ie->type)];

    u8 *v = ((u8 *)grp)+item->offset;

    if (item->is_array)
	r = decode_vector_ie(ie_def, (u8 *)(ie + 1), length, v);
    else
      {
	if (ISSET_BIT(grp->fields, id))
	  /* duplicate IE */
	  vec_add1(grp->ies, ie);
	else
	  r = decode_ie(ie_def, (u8 *)(ie + 1), length, v);
      }

    if (r == 0)
      SET_BIT(grp->fields, id);

 next:
    pos += length + 4;
  }

  return r;
}

int pfcp_decode_msg(u16 type, u8 *p, int len, struct pfcp_group *grp)
{
  assert (type < ARRAY_LEN(msg_specs));
  assert (msg_specs[type].size == 0 || msg_specs[type].group != NULL);

  return decode_group(p, len, &msg_specs[type], grp);
}

static int encode_group(const struct pfcp_ie_def *def, struct pfcp_group *grp, u8 **vec);

static int encode_ie(const struct pfcp_group_ie_def *item,
		     const struct pfcp_ie_def *def,
		     u8 *v, u8 **vec)
{
  int hdr = _vec_len(*vec);
  int r = 0;

  set_ie_hdr_type(*vec, item->type, hdr);
  _vec_len(*vec) += sizeof(pfcp_ie_t);

  if (def->size != 0)
    r = encode_group(def, (struct pfcp_group *)v, vec);
  else
    r = def->encode(v, vec);

  if (r == 0)
    finalize_ie(*vec, hdr, _vec_len(*vec));
  else
    _vec_len(*vec) = hdr;

  return r;
}

static int encode_vector_ie(const struct pfcp_group_ie_def *item,
			    const struct pfcp_ie_def *def,
			    u8 *v, u8 **vec)
{
  u8 *end;
  int r = 0;

  if (!*(u8 **)v)
    return 0;

  end = *(u8 **)v + _vec_len(*(u8 **)v) * def->length;
  for (u8 *p = *(u8 **)v; p < end; p += def->length)
    {
      if ((r = encode_ie(item, def, p, vec)) != 0)
	break;
    }

  return r;
}

static int encode_group(const struct pfcp_ie_def *def, struct pfcp_group *grp, u8 **vec)
{
  int r = 0;

  for (int i = 0; i < def->size; i++)
    {
      const struct pfcp_group_ie_def *item = &def->group[i];
      const struct pfcp_ie_def *ie_def = &group_specs[item->type];
      u8 *v = ((u8 *)grp) + item->offset;

      if (item->type == 0)
	      continue;

      if (!ISSET_BIT(grp->fields, i))
	continue;

      if (item->is_array)
	r = encode_vector_ie(item, ie_def, v, vec);
      else
	r = encode_ie(item, ie_def, v, vec);

      if (r != 0)
	break;
    }

  return r;
}

int pfcp_encode_msg(u16 type, struct pfcp_group *grp, u8 **vec)
{
  assert (type < ARRAY_LEN(msg_specs));
  assert (msg_specs[type].size == 0 || msg_specs[type].group != NULL);

  return encode_group(&msg_specs[type], grp, vec);
}

static void free_group(const struct pfcp_ie_def *def, struct pfcp_group *grp);

static void free_ie(const struct pfcp_group_ie_def *item,
		    const struct pfcp_ie_def *def,
		    u8 *v)
{
  if (def->size != 0)
    free_group(def, (struct pfcp_group *)v);
  else if (def->free)
    def->free(v);
}

static void free_vector_ie(const struct pfcp_group_ie_def *item,
			   const struct pfcp_ie_def *def,
			   u8 *v)
{
  for (u8 *i = *(u8 **)v; i < vec_end(*(u8 **)v); i += def->length)
    free_ie(item, def, i);
  vec_free(*(u8 **)v);
}

static void free_group(const struct pfcp_ie_def *def, struct pfcp_group *grp)
{
  for (int i = 0; i < def->size; i++)
    {
      const struct pfcp_group_ie_def *item = &def->group[i];
      const struct pfcp_ie_def *ie_def = &group_specs[item->type];
      u8 *v = ((u8 *)grp) + item->offset;

      if (item->type == 0)
	      continue;

      if (!ISSET_BIT(grp->fields, i))
	continue;

      if (item->is_array)
	free_vector_ie(item, ie_def, v);
      else
	free_ie(item, ie_def, v);
    }
}

void pfcp_free_msg(u16 type, struct pfcp_group *grp)
{
  assert (type < ARRAY_LEN(msg_specs));
  assert (msg_specs[type].size == 0 || msg_specs[type].group != NULL);

  free_group(&msg_specs[type], grp);
}
