/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

/** @file
    udp gtp_up_sx server
*/

#include <vnet/udp/udp.h>
#include <vnet/session/session.h>
#include <vnet/session/application_interface.h>

#include <vppinfra/bihash_vec8_8.h>
#include <vppinfra/bihash_template.h>

#include <vppinfra/bihash_template.c>

#include "gtp_up_sx_server.h"
#include "gtp_up_sx_api.h"

typedef enum
{
  EVENT_RX = 1,
  EVENT_NOTIFY,
} sx_process_event_t;

typedef struct
{
  u64 session_handle;
  u8 *data;
} sx_server_event_t;

typedef struct
{
  u64 session_handle;
  u8 *node_id;
  u64 node_index;
  u8 *data;
  void *api_session_data;
} sx_server_args;

static sx_server_main_t sx_server_main;

#if 0
static void
free_sx_process (sx_server_args * args)
{
  vlib_node_runtime_t *rt;
  vlib_main_t *vm = &vlib_global_main;
  sx_server_main_t *sx = &sx_server_main;
  vlib_node_t *n;
  u32 node_index;
  sx_server_args **save_args;

  node_index = args->node_index;
  ASSERT (node_index != 0);

  n = vlib_get_node (vm, node_index);
  rt = vlib_node_get_runtime (vm, n->index);
  save_args = vlib_node_get_runtime_data (vm, n->index);

  /* Reset process session pointer */
  clib_mem_free (*save_args);
  *save_args = 0;

  /* Turn off the process node */
  vlib_node_set_state (vm, rt->node_index, VLIB_NODE_STATE_DISABLED);

  /* add node index to the freelist */
  vec_add1 (sx->free_sx_process_node_indices, node_index);
}
#endif

void gtp_up_sx_send_data (stream_session_t * s, u8 * data)
{
  session_fifo_event_t evt;
  u32 offset, bytes_to_send;
  f64 delay = 10e-3;
  sx_server_main_t *sx = &sx_server_main;
  vlib_main_t *vm = sx->vlib_main;
  f64 last_sent_timer = vlib_time_now (vm);

  bytes_to_send = vec_len (data);
  offset = 0;

  while (bytes_to_send > 0)
    {
      int actual_transfer;

      actual_transfer = svm_fifo_enqueue_nowait
	(s->server_tx_fifo, bytes_to_send, data + offset);

      /* Made any progress? */
      if (actual_transfer <= 0)
	{
	  vlib_process_suspend (vm, delay);
	  /* 10s deadman timer */
	  if (vlib_time_now (vm) > last_sent_timer + 10.0)
	    {
	      /* $$$$ FC: reset transport session here? */
	      break;
	    }
	  /* Exponential backoff, within reason */
	  if (delay < 1.0)
	    delay = delay * 2.0;
	}
      else
	{
	  last_sent_timer = vlib_time_now (vm);
	  offset += actual_transfer;
	  bytes_to_send -= actual_transfer;

	  if (svm_fifo_set_event (s->server_tx_fifo))
	    {
	      /* Fabricate TX event, send to vpp */
	      evt.fifo = s->server_tx_fifo;
	      evt.event_type = FIFO_EVENT_APP_TX;

	      svm_queue_add (sx->vpp_queue[s->thread_index], (u8 *) & evt,
			     0 /* do wait for mutex */ );
	    }
	  delay = 10e-3;
	}
    }
}
static int dump_nodes(BVT (clib_bihash_kv) * kvp, void *arg)
{
  clib_warning("K: %s, V: %lld", kvp->key, kvp->value);
  return 0;
}

static uword
sx_process (vlib_main_t * vm,
	    vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  sx_server_main_t *sx = &sx_server_main;
  sx_server_args **save_args;
  sx_server_args *args;
  BVT (clib_bihash_kv) kv;
  BVT (clib_bihash) * h;
  uword *event_data = 0;
  uword event_type;

  save_args = vlib_node_get_runtime_data (sx->vlib_main, rt->node_index);
  args = *save_args;

  clib_warning ("sx process %s, %lld, data %s. ", args->node_id, args->node_index, args->data);

  h = &sx->nodes_hash;
  kv.key = (u64) args->node_id;
  kv.value = args->node_index;
  BV (clib_bihash_add_del) (h, &kv, 1 /* is_add */);

  BV (clib_bihash_foreach_key_value_pair) (h, dump_nodes, NULL);

  while (1)
    {
      if (vec_len(args->data) > 0)
	{
	  stream_session_t *s;

	  s = session_get_from_handle (args->session_handle);
	  ASSERT (s);

	  gtp_up_sx_handle_msg(s, (void *)(args + 1), args->data);
	  // sx_send_data(s, args->data);
	  vec_free(args->data);
	}

      vec_reset_length (event_data);
      vlib_process_wait_for_event (vm);
      event_type = vlib_process_get_events (vm, &event_data);
      switch (event_type)
	{
	case EVENT_RX:
	  {
	    sx_server_event_t *evt = (sx_server_event_t *)event_data[0];
	    clib_warning ("Rx event %p, %ld, %p. ", evt, evt->session_handle, evt->data);
	    args->session_handle = evt->session_handle;
	    args->data = evt->data;

	    clib_mem_free(evt);
	    break;
	  }

	case EVENT_NOTIFY:
	  {
	    sx_server_event_t *evt = (sx_server_event_t *)event_data[0];
	    stream_session_t *s;

	    clib_warning ("NOTIFY event %p, %ld, %p. ", evt, evt->session_handle, evt->data);

	    s = session_get_from_handle (args->session_handle);
	    ASSERT (s);

	    gtp_up_sx_send_data(s, (u8 *)evt->data);

	    vec_free(evt->data);
	    clib_mem_free(evt);
	    break;
	  }
#if 0
	case 2:         /* Stop and Wait for kickoff again */
	  timeout = 1e9;
	  break;
	case 1:         /* kickoff : Check for unsent buffers */
	  timeout = THREAD_PERIOD;
	  break;
#endif
	case ~0:                /* timeout */
	  clib_warning ("timeout....");
	  break;
	default:
	  clib_warning ("event %ld, %p. ", event_type, event_data[0]);
	  break;
	}
    }

  return (0);
}

static void
alloc_sx_process (sx_server_args * args)
{
  char *name;
  vlib_node_t *n;
  sx_server_main_t *sx = &sx_server_main;
  vlib_main_t *vm = sx->vlib_main;
  uword l = vec_len (sx->free_sx_process_node_indices);
  sx_server_args **save_args;

  clib_warning ("alloc sx process %s. ", args->node_id);

  if (vec_len (sx->free_sx_process_node_indices) > 0)
    {
      n = vlib_get_node (vm, sx->free_sx_process_node_indices[l - 1]);
      vlib_node_set_state (vm, n->index, VLIB_NODE_STATE_POLLING);
      _vec_len (sx->free_sx_process_node_indices) = l - 1;
    }
  else
    {
      static vlib_node_registration_t r = {
	.function = sx_process,
	.type = VLIB_NODE_TYPE_PROCESS,
	.process_log2_n_stack_bytes = 16,
	.runtime_data_bytes = sizeof (void *),
      };

      name = (char *) format (0, "sx-api-%d", l);
      r.name = name;
      vlib_register_node (vm, &r);
      vec_free (name);

      n = vlib_get_node (vm, r.index);
    }

  /* Save the node index in the args. It won't be zero. */
  args->node_index = n->index;

  /* Save the args (pointer) in the node runtime */
  save_args = vlib_node_get_runtime_data (vm, n->index);
  *save_args = args;

  vlib_start_process (vm, n->runtime_index);
}

static void
alloc_sx_process_callback (void *cb_args)
{
  alloc_sx_process ((sx_server_args *) cb_args);
}

static int
session_rx_request (stream_session_t * s)
{
  sx_server_main_t *sx = &sx_server_main;
  svm_fifo_t *rx_fifo;
  u32 max_dequeue;
  int actual_transfer;

  rx_fifo = s->server_rx_fifo;
  max_dequeue = svm_fifo_max_dequeue (rx_fifo);
  svm_fifo_unset_event (rx_fifo);
  if (PREDICT_FALSE (max_dequeue == 0))
    return -1;

  vec_validate (sx->rx_buf[s->thread_index], max_dequeue - 1);
  _vec_len (sx->rx_buf[s->thread_index]) = max_dequeue;

  actual_transfer = svm_fifo_dequeue_nowait (rx_fifo, max_dequeue,
					     sx->rx_buf[s->thread_index]);
  ASSERT (actual_transfer > 0);
  _vec_len (sx->rx_buf[s->thread_index]) = actual_transfer;
  return 0;
}

static int
gtp_up_sx_server_rx_callback (stream_session_t * s)
{
  static u8 dummy_name[] = "Sx-API-1";
  sx_server_main_t *sx = &sx_server_main;
  vlib_main_t *vm = sx->vlib_main;
  BVT (clib_bihash_kv) kv;
  BVT (clib_bihash) * h;
  sx_server_args *args;
  u8 * node_id = NULL;
  int rv;

  clib_warning ("called...");

  rv = session_rx_request (s);
  clib_warning ("session_sx_req %d", rv);
  if (rv)
    return rv;

  vec_add (node_id, dummy_name, sizeof(dummy_name));
  vec_add1 (node_id, 0);

  //TODO: find the node_id and forward.... or start a new node process....
  h = &sx->nodes_hash;
  kv.key = (u64) node_id;
  rv = BV (clib_bihash_search) (h, &kv, &kv);
  clib_warning ("nodes bihash got %d, %p, %d. ", rv, (u8 *)kv.key, kv.value);

  BV (clib_bihash_foreach_key_value_pair) (h, dump_nodes, NULL);

  if (rv < 0)
    {
      /* send the command to a new/recycled vlib process */
      args = clib_mem_alloc (sizeof (*args) + gtp_up_sx_api_session_data_size());
      args->node_id = node_id;
      args->data = vec_dup (sx->rx_buf[s->thread_index]);
      args->session_handle = session_handle (s);
      gtp_up_sx_api_session_data_init((void *)(args + 1), sx->start_time);


      clib_warning ("PFCP: start_time: %p, %d, %x.",
		    sx, sx->start_time, sx->start_time);
      clib_warning ("going to alloc sx process %s. ", args->node_id);

      /* Send an RPC request via the thread-0 input node */
      if (vlib_get_thread_index () != 0)
	{
	  session_fifo_event_t evt;
	  evt.rpc_args.fp = alloc_sx_process_callback;
	  evt.rpc_args.arg = args;
	  evt.event_type = FIFO_EVENT_RPC;
	  svm_queue_add (session_manager_get_vpp_event_queue (0 /* main thread */ ),
			 (u8 *) & evt, 0 /* do wait for mutex */ );
	}
      else
	alloc_sx_process (args);
    }
  else
    {
      sx_server_event_t *evt;

      /* signal Sx process to handle data */
      evt = clib_mem_alloc (sizeof (*evt));
      evt->session_handle = session_handle (s);
      evt->data = vec_dup (sx->rx_buf[s->thread_index]);

      clib_warning ("sending event %p, sh: %ld, data %p", evt, evt->session_handle, evt->data);
      vlib_process_signal_event_mt(vm, kv.value, EVENT_RX, (uword)evt);
    }

  vec_reset_length(sx->rx_buf[s->thread_index]);
  return 0;
}

void
gtp_up_sx_server_notify(u64 session_handle, u8 * data)
{
  static u8 dummy_name[] = "Sx-API-1";
  sx_server_main_t *sx = &sx_server_main;
  vlib_main_t *vm = sx->vlib_main;
  BVT (clib_bihash_kv) kv;
  sx_server_event_t *evt;
  BVT (clib_bihash) * h;
  u8 * node_id = NULL;
  int rv;

  clib_warning ("called...");

  vec_add (node_id, dummy_name, sizeof(dummy_name));
  vec_add1 (node_id, 0);

  //TODO: find the node_id and forward.... or start a new node process....
  h = &sx->nodes_hash;
  kv.key = (u64) node_id;
  rv = BV (clib_bihash_search) (h, &kv, &kv);
  clib_warning ("nodes bihash got %d, %p, %d. ", rv, (u8 *)kv.key, kv.value);

  BV (clib_bihash_foreach_key_value_pair) (h, dump_nodes, NULL);

  vec_free(node_id);

  if (rv != 0)
    return;

  /* signal Sx process to handle data */
  evt = clib_mem_alloc (sizeof (*evt));
  evt->session_handle = session_handle;
  evt->data = vec_dup (data);

  clib_warning ("sending NOTIFY event %p, sh: %ld, data %p", evt, evt->data);
  vlib_process_signal_event_mt(vm, kv.value, EVENT_NOTIFY, (uword)evt);
}

/*********************************************************/

static int
gtp_up_sx_session_create_callback (stream_session_t * s)
{
  sx_server_main_t *sx = &sx_server_main;

  clib_warning ("called...");

  sx->vpp_queue[s->thread_index] =
    session_manager_get_vpp_event_queue (s->thread_index);
  s->session_state = SESSION_STATE_READY;
  return 0;
}

static void
gtp_up_sx_session_disconnect_callback (stream_session_t * s)
{
  clib_warning ("called...");

  stream_session_disconnect (s);
}

static void
gtp_up_sx_session_reset_callback (stream_session_t * s)
{
  clib_warning ("Reset session %U", format_stream_session, s, 2);

  stream_session_cleanup (s);
}

static int
gtp_up_sx_session_connected_callback (u32 app_index, u32 api_context,
				    stream_session_t * s, u8 is_fail)
{
  clib_warning ("called...");
  return -1;
}


/* *INDENT-OFF* */
static session_cb_vft_t gtp_up_sx_server = {
    .session_accept_callback = gtp_up_sx_session_create_callback,
    .session_disconnect_callback = gtp_up_sx_session_disconnect_callback,
    .session_connected_callback = gtp_up_sx_session_connected_callback,
    .builtin_server_rx_callback = gtp_up_sx_server_rx_callback,
    .session_reset_callback = gtp_up_sx_session_reset_callback
};
/* *INDENT-ON* */

/* Abuse VPP's input queue */
static int
create_api_loopback (vlib_main_t * vm)
{
  sx_server_main_t *sx = &sx_server_main;
  api_main_t *am = &api_main;
  vl_shmem_hdr_t *shmem_hdr;

  shmem_hdr = am->shmem_hdr;
  sx->vl_input_queue = shmem_hdr->vl_input_queue;
  sx->my_client_index =
    vl_api_memclnt_create_internal ("gtp_up_sx_server", sx->vl_input_queue);
  return 0;
}

static int
attach_gtp_up_sx_uri_server ()
{
  sx_server_main_t *sx = &sx_server_main;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[16];

  memset (a, 0, sizeof (*a));
  memset (options, 0, sizeof (options));

  a->api_client_index = sx->my_client_index;
  a->session_cb_vft = &gtp_up_sx_server;
  a->options = options;
  a->options[APP_OPTIONS_ACCEPT_COOKIE] = 0x12345678;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = (2 << 30);	/*$$$$ config / arg */
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = 1024;

  if (vnet_application_attach (a))
    {
      clib_warning ("failed to attach server");
      return -1;
    }

  sx->app_index = a->app_index;
  return 0;
}

static int
sx_enable_server (vlib_main_t * vm)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  sx_server_main_t *sx = &sx_server_main;
  vnet_bind_args_t _a, *a = &_a;
  u32 num_threads;
  int rv;

  if (sx->my_client_index == (u32) ~ 0)
    {
      if (create_api_loopback (vm))
	{
	  clib_warning ("failed to create api loopback");
	  return -1;
	}
    }

  num_threads = 1 /* main thread */  + vtm->n_threads;
  vec_validate (sx_server_main.vpp_queue, num_threads - 1);

  clib_warning ("attach...");
  rv = attach_gtp_up_sx_uri_server ();
  if (rv)
    return rv;

  memset (a, 0, sizeof (*a));
  a->uri = "udp://0.0.0.0/8805";
  a->app_index = sx->app_index;

  clib_warning ("bind...");
  rv = vnet_bind_uri (a);

  return rv;
}

static int
sx_disable_server ()
{
  vnet_unbind_args_t _a, *a = &_a;

  a->app_index = ~0;
  a->uri = "udp://0.0.0.0/8805";

  return vnet_unbind_uri (a);
}

static clib_error_t *
gtp_up_sx_enable_disable_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  sx_server_main_t *sx = &sx_server_main;
  u8 enable = 1;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	enable = 0;
      else
	{
	  return clib_error_return (0, "unknown input '%U'",
	    format_unformat_error, input);
	}
     }

  if (enable)
    {
      if (sx->app_index != (u32) ~ 0)
	return clib_error_return (0, "Sx API server is already running");

      vnet_session_enable_disable (vm, 1 /* turn on UDP, etc. */ );

      rv = sx_enable_server (vm);
    }
  else
    {
      rv = sx_disable_server ();
      sx->app_index = ~0;
    }

  switch (rv)
    {
    case 0:
      break;

    default:
      return clib_error_return (0, "bind_uri_server returned %d", rv);
      break;
    }

  return 0;
}

VLIB_CLI_COMMAND (gtp_up_sx_enable_disable_command, static) =
{
  .path = "gtp-up sx",
  .short_help = "gtp-up sx [disable]",
  .function = gtp_up_sx_enable_disable_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
sx_server_main_init (vlib_main_t * vm)
{
  sx_server_main_t *sx = &sx_server_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads;

  sx->app_index = ~0;
  sx->vlib_main = vm;
  sx->my_client_index = ~0;
  num_threads = 1 /* main thread */  + vtm->n_threads;
  vec_validate (sx->rx_buf, num_threads - 1);
  BV (clib_bihash_init) (&sx->nodes_hash, "sx-nodes", 2 /*nbuckets */, 3ULL << 30);

  sx->start_time = time(NULL);
  clib_warning ("PFCP: start_time: %p, %d, %x.", sx, sx->start_time, sx->start_time);
  return 0;
}

VLIB_INIT_FUNCTION (sx_server_main_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
