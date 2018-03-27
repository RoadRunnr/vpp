/*
 * Copyright(c) 2017 Travelping GmbH.
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

#ifndef _GTP_UP_SX_SERVER_H
#define _GTP_UP_SX_SERVER_H

#include <time.h>
#include <vnet/session/session.h>
#include <vnet/session/application_interface.h>

typedef struct
{
  u64 node_index;

  /* Sx Node Id is either IPv4, IPv6 or FQDN */
  u8 * node_id;
} sx_node_t;

typedef struct
{
  u8 **rx_buf;
  svm_queue_t **vpp_queue;
  svm_queue_t *vl_input_queue;  /**< Sever's event queue */
  u64 byte_index;

  u32 *free_sx_process_node_indices;

  u32 app_index;
  u32 my_client_index;          /**< API client handle */
  u32 node_index;               /**< process node index for evnt scheduling */

  sx_node_t * nodes;
  BVT (clib_bihash) nodes_hash;

  time_t start_time;

  vlib_main_t *vlib_main;
} sx_server_main_t;

void gtp_up_sx_send_data (stream_session_t * s, u8 * data);
void gtp_up_sx_server_notify(u64 session_handle, u8 * data);

#endif /* _GTP_UP_SX_SERVER_H */
