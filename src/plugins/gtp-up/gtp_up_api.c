/*
 * gtp_up.c - 3GPP TS 29.244 GTP-U UP plug-in for vpp
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

#define _LGPL_SOURCE            /* LGPL v3.0 is compatible with Apache 2.0 */
#include <urcu-qsbr.h>          /* QSBR RCU flavor */

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>

#include <vppinfra/byte_order.h>
#include <vlibmemory/api.h>

#include <gtp-up/gtp_up.h>

/* define message IDs */
#include <gtp-up/gtp_up_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <gtp-up/gtp_up_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <gtp-up/gtp_up_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <gtp-up/gtp_up_all_api_h.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <gtp-up/gtp_up_all_api_h.h>
#undef vl_api_version

#define vl_msg_name_crc_list
#include <gtp-up/gtp_up_all_api_h.h>
#undef vl_msg_name_crc_list

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* List of message types that this plugin understands */

static void
setup_message_id_table (gtp_up_main_t * sm, api_main_t * am)
{
#define _(id,n,crc)   vl_msg_api_add_msg_name_crc (am, #n  #crc, id + sm->msg_id_base);
  foreach_vl_msg_name_crc_gtp_up ;
#undef _
}

#define foreach_gtp_up_plugin_api_msg		\
_(GTP_UP_ENABLE_DISABLE, gtp_up_enable_disable)

/* API message handler */
static void vl_api_gtp_up_enable_disable_t_handler
(vl_api_gtp_up_enable_disable_t * mp)
{
  vl_api_gtp_up_enable_disable_reply_t * rmp;
  gtp_up_main_t * sm = &gtp_up_main;
  int rv;

  rv = gtp_up_enable_disable (sm, ntohl(mp->sw_if_index),
				      (int) (mp->enable_disable));

  REPLY_MACRO(VL_API_GTP_UP_ENABLE_DISABLE_REPLY);
}

/* Set up the API message handling tables */
static clib_error_t *
gtp_up_api_hookup (vlib_main_t *vm)
{
  gtp_up_main_t * sm = &gtp_up_main;

  u8 *name = format (0, "gtp_up_%08x%c", api_version, 0);
  sm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + sm->msg_id_base),     \
			   #n,					\
			   vl_api_##n##_t_handler,              \
			   vl_noop_handler,                     \
			   vl_api_##n##_t_endian,               \
			   vl_api_##n##_t_print,                \
			   sizeof(vl_api_##n##_t), 1);
    foreach_gtp_up_plugin_api_msg;
#undef _

    /* Add our API messages to the global name_crc hash table */
    setup_message_id_table (sm, &api_main);

    return 0;
}

VLIB_API_INIT_FUNCTION (gtp_up_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
