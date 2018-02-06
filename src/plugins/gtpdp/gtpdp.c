/*
 * gtpdp.c - 3GPP TS 29.244 GTP-U DP plug-in for vpp
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

#include <rte_config.h>
#include <rte_common.h>
#include <rte_eal.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <gtpdp/gtpdp.h>
#include <gtpdp/gtpdp_sx.h>
#include <gtpdp/pfcp.h>

/* Action function shared between message handler and debug CLI */

int gtpdp_enable_disable (gtpdp_main_t * sm, u32 sw_if_index,
			  int enable_disable)
{
  vnet_sw_interface_t * sw;
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (sm->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (sm->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vnet_feature_enable_disable ("device-input", "gtpdp",
			       sw_if_index, enable_disable, 0, 0);

  return rv;
}

static clib_error_t *
gtpdp_enable_disable_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  gtpdp_main_t * sm = &gtpdp_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable_disable = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
			 sm->vnet_main, &sw_if_index))
	;
      else
	break;
  }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = gtpdp_enable_disable (sm, sw_if_index, enable_disable);

  switch(rv)
    {
  case 0:
    break;

  case VNET_API_ERROR_INVALID_SW_IF_INDEX:
    return clib_error_return
      (0, "Invalid interface, only works on physical ports");
    break;

  case VNET_API_ERROR_UNIMPLEMENTED:
    return clib_error_return (0, "Device driver doesn't support redirection");
    break;

  default:
    return clib_error_return (0, "gtpdp_enable_disable returned %d",
			      rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gtpdp_enable_disable_command, static) =
{
  .path = "gtpdp enable-disable",
  .short_help =
  "gtpdp enable-disable <interface-name> [disable]",
  .function = gtpdp_enable_disable_command_fn,
};
/* *INDENT-ON* */

int vnet_gtpdp_nwi_add_del(u8 * name, u32 vrf, u8 add)
{
  gtpdp_main_t * gtm = &gtpdp_main;
  gtpdp_nwi_t * nwi;
  uword *p;

  p = hash_get_mem (gtm->nwi_index_by_name, name);

  if (add)
    {
      if (p)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get_aligned (gtm->nwis, nwi, CLIB_CACHE_LINE_BYTES);
      memset (nwi, 0, sizeof (*nwi));

      nwi->name = vec_dup(name);
      nwi->vrf = vrf;
      for (int i = 0; i < ARRAY_LEN(nwi->intf_sw_if_index); i++)
	nwi->intf_sw_if_index[i] = ~0;

      hash_set_mem (gtm->nwi_index_by_name, nwi->name, nwi - gtm->nwis);
    }
  else
    {
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      nwi = pool_elt_at_index (gtm->nwis, p[0]);

      hash_unset_mem (gtm->nwi_index_by_name, nwi->name);
      vec_free (nwi->name);
      pool_put (gtm->nwis, nwi);
     }

  return 0;
}

/**
 * Translate "foo.com" into "0x3 f o o 0x3 c o m 0x0"
 * A historical / hysterical micro-TLV scheme. DGMS.
 */
static u8 *
gtpdp_name_to_labels (u8 * name)
{
  int i;
  int last_label_index;
  u8 *rv;

  rv = vec_dup (name);

  /* punch in space for the first length */
  vec_insert (rv, 1, 0);
  last_label_index = 0;
  i = 1;

  while (i < vec_len (rv))
    {
      if (rv[i] == '.')
	{
	  rv[last_label_index] = (i - last_label_index) - 1;
	  if ((i - last_label_index) > 63)
	    clib_warning ("stupid name, label length %d",
			  i - last_label_index);
	  last_label_index = i;
	  rv[i] = 0;
	}
      i++;
    }
  /* Set the last real label length */
  rv[last_label_index] = (i - last_label_index) - 1;

  return rv;
}

static clib_error_t *
gtpdp_nwi_add_del_command_fn (vlib_main_t * vm,
			      unformat_input_t * main_input,
			      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t * error = NULL;
  u32 vrf = 0;
  u8 *name = NULL;
  u8 *label = NULL;
  u8 add = 1;
  int rv;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	add = 0;
      else if (unformat (line_input, "add"))
	add = 1;
      else if (unformat (line_input, "name %_%v%_", &name))
	;
      else if (unformat (line_input, "label %_%v%_", &label))
	;
      else if (unformat (line_input, "vrf %d", &vrf))
	;
      else {
	error = unformat_parse_error (line_input);
	goto done;
      }
    }

  if (!name && !label)
    return clib_error_return (0, "name or label must be specified!");

  if (!name)
    name = gtpdp_name_to_labels(label);

  rv = vnet_gtpdp_nwi_add_del(name, vrf, add);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "network instance already exists...");
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "network instance does not exist...");
      break;

    default:
      error = clib_error_return
	(0, "vnet_gtpdp_nwi_add_del returned %d", rv);
      break;
    }

done:
  vec_free (name);
  vec_free (label);
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gtpdp_nwi_add_del_command, static) =
{
  .path = "gtpdp nwi create",
  .short_help =
  "gtpdp nwi create [name <name> | dns <label>] [vrf <vrf>]",
  .function = gtpdp_nwi_add_del_command_fn,
};
/* *INDENT-ON* */

#if 0
static void vtep_ip4_ref(ip4_address_t * ip, u8 ref)
{
  uword *vtep = hash_get (gtpdp_main.vtep4, ip->as_u32);
  if (ref)
    {
      if (vtep)
	++(*vtep);
      else
	hash_set (gtpdp_main.vtep4, ip->as_u32, 1);
    }
  else
    {
      if (!vtep)
	return;

      if (--(*vtep) == 0)
	hash_unset (gtpdp_main.vtep4, ip->as_u32);
    }
}

static void vtep_ip6_ref(ip6_address_t * ip, u8 ref)
{
  uword *vtep = hash_get_mem (gtpdp_main.vtep6, ip);
  if (ref)
    {
      if (vtep)
	++(*vtep);
      else
	hash_set_mem_alloc (&gtpdp_main.vtep6, ip, 1);
    }
  else
    {
      if (!vtep)
	return;

      if (--(*vtep) == 0)
	hash_unset_mem_free (&gtpdp_main.vtep6, ip);
    }
}

static void vtep_if_address_add_del(u32 sw_if_index, u8 add)
{
  ip_lookup_main_t *lm4 = &ip4_main.lookup_main;
  ip_lookup_main_t *lm6 = &ip6_main.lookup_main;
  ip_interface_address_t *ia = 0;
  ip4_address_t *ip4;
  ip6_address_t *ip6;

  foreach_ip_interface_address (lm4, ia, sw_if_index, 1 /* unnumbered */ ,
  ({
    ip4 = ip_interface_address_get_address (lm4, ia);
    vtep_ip4_ref(ip4, add);
  }));
  foreach_ip_interface_address (lm6, ia, sw_if_index, 1 /* unnumbered */ ,
  ({
    ip6 = ip_interface_address_get_address (lm6, ia);
    vtep_ip6_ref(ip6, add);
  }));
}
#endif

int vnet_gtpdp_nwi_set_addr(u8 * name, ip46_address_t *ip, u32 teid, u32 mask, u8 add)
{
  gtpdp_main_t * gtm = &gtpdp_main;
  gtpdp_nwi_ip_res_t *ip_res;
  gtpdp_nwi_t * nwi;
  uword *p;

  p = hash_get_mem (gtm->nwi_index_by_name, name);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  nwi = pool_elt_at_index (gtm->nwis, p[0]);
  if (!nwi->ip_res_index_by_ip)
    nwi->ip_res_index_by_ip =
      hash_create_mem (0, sizeof (ip46_address_t), sizeof (uword));

  p = hash_get_mem (nwi->ip_res_index_by_ip, ip);

  if (add)
    {
      if (p)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get_aligned (nwi->ip_res, ip_res, CLIB_CACHE_LINE_BYTES);
      memset (ip_res, 0, sizeof (*ip_res));

      ip_res->ip = *ip;
      ip_res->teid = teid & mask;
      ip_res->mask = mask;

      hash_set_mem_alloc(&nwi->ip_res_index_by_ip, &ip_res->ip, ip_res - nwi->ip_res);
    }
  else
    {
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      ip_res = pool_elt_at_index (nwi->ip_res, p[0]);
      hash_unset_mem_free (&nwi->ip_res_index_by_ip, &ip_res->ip);
      pool_put(nwi->ip_res, ip_res);
    }

  return 0;
}

clib_error_t *
gtpdp_nwi_set_addr_command_fn (vlib_main_t * vm,
			       unformat_input_t * main_input,
			       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t * error = NULL;
  u32 addr_set = 0;
  ip46_address_t ip;
  u32 teid = 0, mask = 0, teidri = 0;
  u8 *name = NULL;
  u8 *label = NULL;
  u8 add = 1;
  int rv;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	add = 0;
      else if (unformat (line_input, "add"))
	add = 1;
      else if (unformat (line_input, "name %_%v%_", &name))
	;
      else if (unformat (line_input, "label %_%v%_", &label))
	;
      else if (unformat (line_input, "%U", unformat_ip46_address, &ip, IP46_TYPE_ANY))
	addr_set = 1;
      else if (unformat (line_input, "teid %u/%u", &teid, &teidri))
	{
	  if (teidri > 7) {
	    error = clib_error_return (0, "TEID Range Indication to large (%d > 7)", teidri);
	    goto done;
	  }
	  mask = 0xfe000000 << (7 - teidri);
	}
      else if (unformat (line_input, "teid 0x%x/%u", &teid, &teidri))
	{
	  if (teidri > 7) {
	    error = clib_error_return (0, "TEID Range Indication to large (%d > 7)", teidri);
	    goto done;
	  }
	  mask = 0xfe000000 << (7 - teidri);
	}
      else {
	error = unformat_parse_error (line_input);
	goto done;
      }
    }

  if (!addr_set)
    {
      error = clib_error_return (0, "No IP address provided");
      goto done;
    }
  if (!name && !label)
    {
      error = clib_error_return (0, "name or label must be specified");
      goto done;
    }

  if (!name)
    name = gtpdp_name_to_labels(label);

  rv = vnet_gtpdp_nwi_set_addr(name, &ip, teid, mask, add);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_VALUE_EXIST:
      error = clib_error_return (0, "IP resource already exists...");
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "network instance or IP resource does not exist...");
      break;

    default:
      error = clib_error_return
	(0, "vnet_gtpdp_nwi_set_addr returned %d", rv);
      break;
    }

 done:
  vec_free (name);
  vec_free (label);
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gtpdp_nwi_set_addr_command, static) =
{
  .path = "gtpdp nwi set gtpu address",
  .short_help =
  "gtpdp nwi set gtpu address [name <name> | dns <label>] <address> [teid <teid>/<mask>] [del]",
  .function = gtpdp_nwi_set_addr_command_fn,
};
/* *INDENT-ON* */

int vnet_gtpdp_nwi_set_intf_role(u8 * name, u8 intf, u32 sw_if_index, u8 add)
{
  gtpdp_main_t * gtm = &gtpdp_main;
  gtpdp_nwi_t * nwi;
  uword *p;

  if (intf >= INTF_NUM)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  p = hash_get_mem (gtm->nwi_index_by_name, name);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  nwi = pool_elt_at_index (gtm->nwis, p[0]);

  if (add)
    nwi->intf_sw_if_index[intf] = sw_if_index;
  else
    nwi->intf_sw_if_index[intf] = ~0;

  return 0;
}

clib_error_t *
gtpdp_nwi_set_intf_role_command_fn (vlib_main_t * vm,
				    unformat_input_t * main_input,
				    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t * error = NULL;
  u8 *name = NULL;
  u8 *label = NULL;
  u8 intf = ~0;
  u32 sw_if_index = ~0;
  u8 add = 1;
  int rv;

  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	add = 0;
      else if (unformat (line_input, "add"))
	add = 1;
      else if (unformat (line_input, "name %_%v%_", &name))
	;
      else if (unformat (line_input, "label %_%v%_", &label))
	;
      else if (unformat (line_input, "interface %U",
			   unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (line_input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (line_input, "access"))
	intf = INTF_ACCESS;
      else if (unformat (line_input, "core"))
	intf = INTF_CORE;
      else if (unformat (line_input, "sgi"))
	intf = INTF_SGI_LAN;
      else if (unformat (line_input, "cp"))
	intf = INTF_CP;
      else if (unformat (line_input, "li"))
	intf = INTF_LI;
      else {
	error = unformat_parse_error (line_input);
	goto done;
      }
    }

  if (intf == (u8)~0)
    {
      error = clib_error_return (0, "Interface type not specified");
      goto done;
    }
  if (sw_if_index == ~0)
    {
      error = clib_error_return (0, "Interface or sw_if_index not specified");
      goto done;
    }
  if (!name && !label)
    {
      error = clib_error_return (0, "name or label must be specified");
      goto done;
    }

  if (!name)
    name = gtpdp_name_to_labels(label);

  rv = vnet_gtpdp_nwi_set_intf_role(name, intf, sw_if_index, add);

  switch (rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "network instance does not exist...");
      break;

    default:
      error = clib_error_return
	(0, "vnet_gtpdp_nwi_set_intf_role returned %d", rv);
      break;
    }

 done:
  vec_free (name);
  vec_free (label);
  unformat_free (line_input);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gtpdp_nwi_set_intf_role_command, static) =
{
  .path = "gtpdp nwi set interface type",
  .short_help =
  "gtpdp nwi set interface type [name <name> | dns <label>] [access | core | sgi | cp] [interface <interface> | sw_if_index <inde>] [del]",
  .function = gtpdp_nwi_set_intf_role_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
gtpdp_show_nwi_command_fn (vlib_main_t * vm,
			   unformat_input_t * main_input,
			   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  gtpdp_main_t * gtm = &gtpdp_main;
  clib_error_t * error = NULL;
  gtpdp_nwi_t * nwi;
  u8 *label = NULL;
  u8 *name = NULL;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "name %_%v%_", &name))
	    ;
	  else if (unformat (line_input, "label %_%v%_", &label))
	    ;
	  else {
	    error = unformat_parse_error (line_input);
	    unformat_free (line_input);
	    goto done;
	  }
	}

      unformat_free (line_input);
    }

  if (!name && label)
    name = gtpdp_name_to_labels(label);

  pool_foreach (nwi, gtm->nwis,
    ({
      gtpdp_nwi_ip_res_t * ip_res;

      if (name && !vec_is_equal(name, nwi->name))
	continue;

      vlib_cli_output (vm, "%U: vrf: %d", format_network_instance, nwi->name, nwi->vrf);
      vlib_cli_output (vm, "  Access: %U", format_vnet_sw_if_index_name,
		       vnm, nwi->intf_sw_if_index[INTF_ACCESS]);
      vlib_cli_output (vm, "  Core: %U", format_vnet_sw_if_index_name,
		       vnm, nwi->intf_sw_if_index[INTF_CORE]);
      vlib_cli_output (vm, "  SGi LAN: %U", format_vnet_sw_if_index_name,
		       vnm, nwi->intf_sw_if_index[INTF_SGI_LAN]);
      vlib_cli_output (vm, "  CP: %U", format_vnet_sw_if_index_name,
		       vnm, nwi->intf_sw_if_index[INTF_CP]);
      vlib_cli_output (vm, "  LI: %U", format_vnet_sw_if_index_name,
		       vnm, nwi->intf_sw_if_index[INTF_LI]);

      vlib_cli_output (vm, "  IPs: %d", pool_elts(nwi->ip_res));

      pool_foreach (ip_res, nwi->ip_res,
	({
	  vlib_cli_output (vm, "  [%d]: vrf: %U, teid: 0x%08x/%d (0x%08x)",
			   ip_res - nwi->ip_res,
			   format_ip46_address, &ip_res->ip, IP46_TYPE_ANY,
			   ip_res->teid, __builtin_popcount(ip_res->mask),
			   ip_res->mask);
	}));
    }));

done:
  vec_free (name);
  vec_free (label);
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gtpdp_show_nwi_command, static) =
{
  .path = "show gtpdp nwi",
  .short_help =
  "show gtpdp nwi",
  .function = gtpdp_show_nwi_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
gtpdp_show_session_command_fn (vlib_main_t * vm,
			       unformat_input_t * main_input,
			       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  gtpdp_main_t * gtm = &gtpdp_main;
  clib_error_t * error = NULL;
  u64 cp_seid, up_seid;
  ip46_address_t cp_ip;
  u8 has_cp_f_seid = 0, has_up_seid = 0;
  gtpdp_session_t *sess;

  if (unformat_user (main_input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "cp %U seid %lu",
			unformat_ip46_address, &cp_ip, IP46_TYPE_ANY, &cp_seid))
	    has_cp_f_seid = 1;
	  else if (unformat (line_input, "cp %U seid 0x%lx",
			     unformat_ip46_address, &cp_ip, IP46_TYPE_ANY, &cp_seid))
	    has_cp_f_seid = 1;
	  else if (unformat (line_input, "up seid %lu", &up_seid))
	    has_up_seid = 1;
	  else if (unformat (line_input, "up seid 0x%lx", &up_seid))
	    has_up_seid = 1;
	  else {
	    error = unformat_parse_error (line_input);
	    unformat_free (line_input);
	    goto done;
	  }
	}

      unformat_free (line_input);
    }

  if (has_cp_f_seid)
    {
      error = clib_error_return (0, "CP F_SEID is not supported, yet");
      goto done;
    }

  if (has_up_seid)
    {
      if (!(sess = sx_lookup(up_seid)))
	{
	  error = clib_error_return (0, "Sessions %d not found", up_seid);
	  goto done;
	}

      vlib_cli_output (vm, "%U", format_sx_session, sess, SX_ACTIVE);
    }
  else
      pool_foreach (sess, gtm->sessions,
	({
	  vlib_cli_output (vm, "%U", format_sx_session, sess, SX_ACTIVE);
	}));

 done:
  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (gtpdp_show_session_command, static) =
{
  .path = "show gtpdp session",
  .short_help =
  "show gtpdp session",
  .function = gtpdp_show_session_command_fn,
};
/* *INDENT-ON* */

static clib_error_t * gtpdp_init (vlib_main_t * vm)
{
  gtpdp_main_t * sm = &gtpdp_main;
  char *argv[] = { "gtpdp", "--no-huge", "--no-pci", NULL };
  int ret;

  sm->vnet_main = vnet_get_main ();
  sm->vlib_main = vm;

  ret = rte_eal_init (3, argv);
  if (ret < 0)
    return clib_error_return (0, "rte_eal_init returned %d", ret);

  sm->nwi_index_by_name =
    hash_create_vec ( /* initial length */ 32, sizeof (u8), sizeof (uword));

  /* initialize the ip6 hash */
  sm->v6_tunnel_by_key = hash_create_mem (0,
					  sizeof (gtpu6_tunnel_key_t),
					  sizeof (uword));
  sm->v6_peer = hash_create_mem (0, sizeof (ip6_address_t), sizeof (uword));
#if 0
  sm->vtep6 = hash_create_mem (0, sizeof (ip6_address_t), sizeof (uword));
#endif

  udp_register_dst_port (vm, UDP_DST_PORT_GTPU,
			 gtpu4_input_node.index, /* is_ip4 */ 1);
  udp_register_dst_port (vm, UDP_DST_PORT_GTPU6,
			 gtpu6_input_node.index, /* is_ip4 */ 0);

  sm->fib_node_type = fib_node_register_new_type (&gtpdp_vft);

  return 0;
}

VLIB_INIT_FUNCTION (gtpdp_init);

/* *INDENT-OFF* */
VNET_FEATURE_INIT (gtpdp, static) =
{
  .arc_name = "device-input",
  .node_name = "gtpdp",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
/* *INDENT-ON */

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
