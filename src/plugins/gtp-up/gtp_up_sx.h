/*
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

#ifndef _GTP_UP_SX_H_
#define _GTP_UP_SX_H_

#include "gtp_up.h"

#define MAX_LEN 128

gtp_up_node_assoc_t *sx_get_association(pfcp_node_id_t *node_id);
gtp_up_node_assoc_t *sx_new_association(pfcp_node_id_t *node_id);
void sx_release_association(gtp_up_node_assoc_t *n);

gtp_up_session_t *sx_create_session(uint64_t cp_f_seid, u64 session_handle);
void sx_update_session(gtp_up_session_t *sx);
int sx_disable_session(gtp_up_session_t *sx);
void sx_free_session(gtp_up_session_t *sx);

#define sx_rule_vector_fns(t)						\
gtp_up_##t##_t * sx_get_##t##_by_id(struct rules *,			\
				   typeof (((gtp_up_##t##_t *)0)->id) t##_id);	\
gtp_up_##t##_t *sx_get_##t(gtp_up_session_t *sx, int rule,		\
			  typeof (((gtp_up_##t##_t *)0)->id) t##_id);	\
int sx_create_##t(gtp_up_session_t *sx, gtp_up_##t##_t *t);		\
int sx_delete_##t(gtp_up_session_t *sx, u32 t##_id);			\

sx_rule_vector_fns(pdr)
sx_rule_vector_fns(far)
sx_rule_vector_fns(urr)

void sx_send_end_marker(gtp_up_session_t *sx, u16 id);

#undef sx_rule_vector_fns

int sx_update_apply(gtp_up_session_t *sx);
void sx_update_finish(gtp_up_session_t *sx);

gtp_up_session_t *sx_lookup(uint64_t sess_id);

u8 * format_sx_session(u8 * s, va_list * args);
void sx_session_dump_tbls(void);

static inline struct rules *sx_get_rules(gtp_up_session_t *sx, int rules)
{
	return &sx->rules[sx->active ^ rules];
}

void vlib_free_combined_counter (vlib_combined_counter_main_t * cm);

void process_urrs(vlib_main_t *vm, struct rules *r,
		  gtp_up_pdr_t *pdr, vlib_buffer_t * b,
		  u8 is_dl, u8 is_ul);

void gtp_up_sx_error_report(gtp_up_session_t * sx, gtp_error_ind_t * error);

#endif /* _GTP_UP_SX_H_ */
