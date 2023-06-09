
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

#include <stdio.h>
#include <string>
#include <unistd.h>

#include "sgx_urts.h"
#include "error_codes.h"
#include "datatypes.h"
#include "Enclave_u.h"

ATTESTATION_STATUS ocall_session_request(sgx_enclave_id_t target_enclave_id, sgx_dh_msg1_t* dh_msg1, sgx_enclave_id_t origin)
{
	sgx_status_t ret;
	uint32_t retcode;

	ret = ecall_session_request(target_enclave_id, &retcode, dh_msg1, origin);
	if (ret != SGX_SUCCESS || retcode != SGX_SUCCESS)
		return ATTESTATION_ERROR;

	return (ATTESTATION_STATUS)0;
}

ATTESTATION_STATUS ocall_exchange_report(sgx_enclave_id_t target_enclave_id, sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3, sgx_enclave_id_t origin)
{
	sgx_status_t ret;
	uint32_t retcode;

	ret = ecall_exchange_report(target_enclave_id, &retcode, dh_msg2, dh_msg3, origin);
	if (ret != SGX_SUCCESS || retcode != SGX_SUCCESS)
		return ATTESTATION_ERROR;

	return (ATTESTATION_STATUS)0;
}

ATTESTATION_STATUS ocall_send_request(sgx_enclave_id_t target_enclave_id, sgx_enclave_id_t origin, secure_message_t* req_message, size_t req_message_size, size_t max_payload_size, secure_message_t* resp_message, size_t resp_message_size)
{
	sgx_status_t ret;
	uint32_t retcode;

	ret = ecall_generate_response(target_enclave_id, &retcode, req_message, req_message_size, max_payload_size, resp_message, resp_message_size, origin);
	if (ret != SGX_SUCCESS || retcode != SGX_SUCCESS)
		return INVALID_SESSION;

	return (ATTESTATION_STATUS)0;
}

ATTESTATION_STATUS ocall_end_session(sgx_enclave_id_t target_enclave_id, sgx_enclave_id_t origin)
{
	sgx_status_t ret;
	uint32_t retcode;

	ret = ecall_end_session(target_enclave_id, &retcode, origin);
	if (ret != SGX_SUCCESS || retcode != SGX_SUCCESS)
		return INVALID_SESSION;

	return (ATTESTATION_STATUS)0;
}