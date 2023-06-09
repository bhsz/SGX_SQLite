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

#include "stdlib.h"
#include "string.h"
#include <stdio.h>
#include "Enclave_t.h"
#include "Utility.h"


// *** INITIATOR ***

// Sharing

uint32_t marshal_message_exchange_request(
    uint32_t target_fn_id,
    uint32_t msg_type,
    char** marshalled_buff,
    size_t* marshalled_buff_len
)
{
    ms_in_msg_exchange_t *ms;
    size_t ms_len;
    if(!marshalled_buff_len)
        return INVALID_PARAMETER_ERROR;
    ms_len = sizeof(ms_in_msg_exchange_t);
    ms = (ms_in_msg_exchange_t *)malloc(ms_len);
    if(!ms)
        return MALLOC_ERROR;

    ms->msg_type = msg_type;
    ms->target_fn_id = target_fn_id;
    ms->inparam_buff_len = 0;

    *marshalled_buff = (char*)ms;
    *marshalled_buff_len = ms_len;

    return SUCCESS;
}

uint32_t unmarshal_message_exchange_response(char* out_buff, char** secret_response, size_t* len)
{
    size_t retval_len;
    ms_out_msg_exchange_t *ms;
    if(!out_buff)
        return INVALID_PARAMETER_ERROR;
    ms = (ms_out_msg_exchange_t *)out_buff;
    retval_len = ms->retval_len;
    *secret_response = (char*)malloc(retval_len);
    if(!*secret_response)
    {
        return MALLOC_ERROR;
    }
    memcpy(*secret_response, ms->ret_outparam_buff, retval_len);
    *len = retval_len;
    return SUCCESS;
}


// *** RESPONDER ***

// Sharing

uint32_t unmarshal_message_exchange_request(char* store, ms_in_msg_exchange_t* ms)
{
    char* buff;
    size_t len;
    if(!ms)
        return INVALID_PARAMETER_ERROR;    
    buff = ms->inparam_buff;
    len = ms->inparam_buff_len;

    // From sample code where data transfer is a single uint32_t
    // if(len != sizeof(uint32_t))
        // return ATTESTATION_ERROR;
    memcpy(store, buff, len);

    return SUCCESS;
}

uint32_t marshal_message_exchange_response(
    char** resp_buffer,
    size_t* resp_length,
    const char* secret_response,
    size_t secret_length
)
{
    ms_out_msg_exchange_t *ms;
    size_t secret_response_len, ms_len;
    size_t retval_len, ret_param_len;
    if(!resp_length)
        return INVALID_PARAMETER_ERROR;    
    secret_response_len = secret_length;
    retval_len = secret_response_len;
    ret_param_len = secret_response_len;
    ms_len = sizeof(ms_out_msg_exchange_t) + ret_param_len;
    ms = (ms_out_msg_exchange_t *)malloc(ms_len);
    if(!ms)
        return MALLOC_ERROR;
    ms->retval_len = (uint32_t)retval_len;
    ms->ret_outparam_buff_len = (uint32_t)ret_param_len;
    memcpy(ms->ret_outparam_buff, secret_response, secret_length);
    *resp_buffer = (char*)ms;
    *resp_length = ms_len;
    return SUCCESS;
}


// Utils

void print(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}
