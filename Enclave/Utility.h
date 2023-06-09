/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef DATAENCLAVEUTILITY_H__
#define DATAENCLAVEUTILITY_H__

#include <vector>
#include "stdint.h"
#include "datatypes.h"

#ifdef __cplusplus
extern "C" {
#endif

// *** INITIATOR ***
uint32_t marshal_message_exchange_request(
    uint32_t target_fn_id,
    uint32_t msg_type,
    char** marshalled_buff,
    size_t* marshalled_buff_len
);
uint32_t unmarshal_message_exchange_response(
    char* out_buff,
    char** secret_response,
    size_t* len
);

// *** RESPONDER ***
uint32_t unmarshal_message_exchange_request(
    char* store,
    ms_in_msg_exchange_t* ms
);
uint32_t marshal_message_exchange_response(
    char** resp_buffer,
    size_t* resp_length,
    const char* secret_response,
    size_t secret_length
);

// Utils
void print(const char *fmt, ...);

#ifdef __cplusplus
}
#endif
#endif
