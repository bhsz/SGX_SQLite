#include "sgx_trts.h"
#include "error_codes.h"
#include "datatypes.h"
#include "dh_session_protocol.h"

#ifndef MESSAGEEXCHANGE_H_
#define MESSAGEEXCHANGE_H_

uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity);
ATTESTATION_STATUS create_session(sgx_enclave_id_t target_enclave_id, dh_session_t** session_info);
ATTESTATION_STATUS send_request_receive_response(
    sgx_enclave_id_t target_enclave_id,
    dh_session_t *session_info,
    char *inp_buff,
    size_t inp_buff_len,
    size_t max_out_buff_size,
    char **out_buff,
    size_t* out_buff_len
);
ATTESTATION_STATUS close_session(sgx_enclave_id_t target_enclave_id);

#endif