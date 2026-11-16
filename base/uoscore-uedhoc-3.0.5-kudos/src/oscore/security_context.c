/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oscore.h"

#include "oscore/aad.h"
#include "oscore/nonce.h"
#include "oscore/oscore_coap.h"
#include "oscore/oscore_hkdf_info.h"
#include "oscore/oscore_interactions.h"
#include "oscore/security_context.h"
#include "oscore/nvm.h"

#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"
#include "common/print_util.h"
#include "common/unit_test.h"

#include "edhoc/bstr_encode_decode.h"
#include "edhoc/hkdf_info.h"
#include "edhoc/buffer_sizes.h"


/**
 * @brief       Common derive procedure used to derive the Common IV and 
 *              Sender / Recipient Keys
 * @param cc    pointer to the common context
 * @param id    empty array for Common IV, sender / recipient ID for keys
 * @param type  IV for Common IV, KEY for Sender / Recipient Keys
 * @param out   out-array. Must be initialized
 * @return      err
 */
STATIC enum err derive(struct common_context *cc, struct byte_array *id,
		       enum derive_type type, struct byte_array *out)
{
	BYTE_ARRAY_NEW(info, MAX_INFO_LEN, MAX_INFO_LEN);
	TRY(oscore_create_hkdf_info(id, &cc->id_context, cc->aead_alg, type,
				    &info));

	PRINT_ARRAY("info struct", info.ptr, info.len);

	switch (cc->kdf) {
	case OSCORE_SHA_256:
		TRY(hkdf_sha_256(&cc->master_secret, &cc->master_salt, &info,
				 out));
		break;
	default:
		return oscore_unknown_hkdf;
		break;
	}
	return ok;
}

/**
 * @brief    Derives the Common IV 
 * @param    cc    pointer to the common context
 * @return   err
 */
static enum err derive_common_iv(struct common_context *cc)
{
	TRY(derive(cc, &EMPTY_ARRAY, IV, &cc->common_iv));
	PRINT_ARRAY("Common IV", cc->common_iv.ptr, cc->common_iv.len);
	return ok;
}

/**
 * @brief    Derives the Sender Key 
 * @param    cc    pointer to the common context
 * @param    sc    pointer to the sender context
 * @return   err
 */
static enum err derive_sender_key(struct common_context *cc,
				  struct sender_context *sc)
{
	TRY(derive(cc, &sc->sender_id, KEY, &sc->sender_key));
	PRINT_ARRAY("Sender Key", sc->sender_key.ptr, sc->sender_key.len);
	return ok;
}

/**
 * @brief    Derives the Recipient Key 
 * @param    cc    pointer to the common context
 * @param    sc    pointer to the recipient context
 * @return   err
 */
static enum err derive_recipient_key(struct common_context *cc,
				     struct recipient_context *rc)
{
	TRY(derive(cc, &rc->recipient_id, KEY, &rc->recipient_key));

	PRINT_ARRAY("Recipient Key", rc->recipient_key.ptr,
		    rc->recipient_key.len);
	return ok;
}

enum err oscore_context_init(struct oscore_init_params *params,
			     struct context *c)
{
	/*derive common context************************************************/

	if (params->aead_alg != OSCORE_AES_CCM_16_64_128) {
		return oscore_invalid_algorithm_aead;
	} else {
		c->cc.aead_alg =
			OSCORE_AES_CCM_16_64_128; /*that's the default*/
	}

	if (params->hkdf != OSCORE_SHA_256) {
		return oscore_invalid_algorithm_hkdf;
	} else {
		c->cc.kdf = OSCORE_SHA_256; /*that's the default*/
	}

        c->cc.fresh_master_secret_salt = params->fresh_master_secret_salt;
	c->cc.master_secret = params->master_secret;
	c->cc.master_salt = params->master_salt;
	c->cc.id_context = params->id_context;
	c->cc.common_iv.len = sizeof(c->cc.common_iv_buf);
	c->cc.common_iv.ptr = c->cc.common_iv_buf;
	TRY(derive_common_iv(&c->cc));

	c->cc.master_secret_old.len = 0;
	c->cc.master_secret_old.ptr = NULL;

	/*derive Recipient Context*********************************************/
	c->rc.notification_num_initialized = false;
	server_replay_window_init(&c->rc.replay_window);
	c->rc.recipient_id.len = params->recipient_id.len;
	c->rc.recipient_id.ptr = c->rc.recipient_id_buf;
	memcpy(c->rc.recipient_id.ptr, params->recipient_id.ptr,
	       params->recipient_id.len);
	c->rc.recipient_key.len = sizeof(c->rc.recipient_key_buf);
	c->rc.recipient_key.ptr = c->rc.recipient_key_buf;
	TRY(derive_recipient_key(&c->cc, &c->rc));

	/*derive Sender Context************************************************/
	c->sc.sender_id = params->sender_id;
	c->sc.sender_key.len = sizeof(c->sc.sender_key_buf);
	c->sc.sender_key.ptr = c->sc.sender_key_buf;
	struct nvm_key_t nvm_key = { .sender_id = c->sc.sender_id,
				     .recipient_id = c->rc.recipient_id,
				     .id_context = c->cc.id_context };

	TRY(ssn_init(&nvm_key, &c->sc.ssn, params->fresh_master_secret_salt));
	TRY(derive_sender_key(&c->cc, &c->sc));

	/*set up the request response context**********************************/
	oscore_interactions_init(c->rrc.interactions);
	c->rrc.nonce.len = sizeof(c->rrc.nonce_buf);
	c->rrc.nonce.ptr = c->rrc.nonce_buf;
	c->rrc.echo_opt_val.len = sizeof(c->rrc.echo_opt_val_buf);
	c->rrc.echo_opt_val.ptr = c->rrc.echo_opt_val_buf;

	c->rrc.kudos_nonce_1.len = 0;
	c->rrc.kudos_nonce_1.ptr = NULL;

	c->rrc.kudos_nonce_2.len = 0;
	c->rrc.kudos_nonce_2.ptr = NULL;

	c->rrc.kudos_x1 = 0;
	c->rrc.kudos_x2 = 0;

	/* no ECHO challenge needed if the context is fresh */
	c->rrc.echo_state_machine =
		(params->fresh_master_secret_salt ? ECHO_SYNCHRONIZED :
						    ECHO_REBOOT);

	return ok;
}

int is_lexicographically_shorter(const struct byte_array *a,
                                 const struct byte_array *b)
{


	if (a->len < b->len) {
		return 1;
	}
	else if (b->len < a->len) {
		return 0;
	}



    uint32_t min_len = (a->len < b->len) ? a->len : b->len;

    // Compare byte by byte
    int cmp = memcmp(a->ptr, b->ptr, min_len);
    if (cmp < 0)
        return 1;               // a < b
    else if (cmp > 0)
        return 0;               // a > b

    // If equal up to the shortest length, the shorter one is lexicographically smaller
    return (a->len < b->len);
}

/* KUDOS-Expand(CTX_IN.MasterSecret, ExpandLabel, key_length) =
   HKDF-Expand(CTX_IN.MasterSecret, ExpandLabel, key_length)*/
enum err kudos_kdf(enum hash_alg hash_alg, const struct byte_array *oldMSecret,
		   char *label, struct byte_array *context,
		   struct byte_array *newMSecret)
{
	PRINTF("context->len: %d\n", context->len);

	// KEY DERIVATION IN THE EDHOC MODE (CBOR HKDF_INFO):
	//uint8_t info_array_max_size = AS_BSTR_SIZE(2 + 2*MAX_NONCE_LEN) + (2 * CBOR_ENCODED_UINT);
	//BYTE_ARRAY_NEW(info, info_array_max_size, AS_BSTR_SIZE(context->len) + (2 * CBOR_ENCODED_UINT));

	//PRINTF("Label for info der:%d\n",label);

	//TRY(create_hkdf_info(label, context, newMSecret->len, &info));

	// NEW KEY DERIVATION IN THE TLS MODE:
	// Size = key_length + 1 + label + 1 + X_N; --> TLS opaque formats.
	uint8_t label_len = strlen(label);
	uint8_t info_array_max_size = 2 + 1 + label_len + 1 + (2 + 2*MAX_NONCE_LEN);
	BYTE_ARRAY_NEW(info, info_array_max_size, 4 + label_len + context->len);

	uint8_t used = 0;
	info.ptr[used++] = 0x00;
	info.ptr[used++] = newMSecret->len;
	info.ptr[used++] = label_len;
	memcpy(&info.ptr[used], label, label_len);
	used += label_len;
	info.ptr[used++] = context->len;
	memcpy(&info.ptr[used], context->ptr, context->len);
	used += context->len;
	info.len = used;

	PRINT_ARRAY("info", info.ptr, info.len);
	return hkdf_expand(hash_alg, oldMSecret, &info, newMSecret);
}


/*
  // Define the label for the key update
  Label = "key update"

  input1 = X1 | N1
  input2 = X2 | N2

  // Create CBOR byte strings from input1 and input2
  input1_cbor = create_cbor_bstr(input1)
  input2_cbor = create_cbor_bstr(input2)

  // Concatenate the CBOR-encoded input1 and input2
  // according to their lexicographic order
  X_N = is_lexicographically_shorter(input1_cbor, input2_cbor) ?
        (input1_cbor | input2_cbor) : (input2_cbor | input1_cbor)

  // Set the new Master Salt to X_N
  MSALT_NEW = X_N

  // Determine the length in bytes of the current Master Secret
  oscore_key_length = length(CTX_IN.MasterSecret)

  // Create the new Master Secret using KUDOS_Expand_Label
  MSECRET_NEW = KUDOS_Expand_Label(CTX_IN.MasterSecret, Label,
                                   X_N, oscore_key_length)
*/
enum err oscore_context_update(struct byte_array *N1, uint8_t X1, struct byte_array *N2, uint8_t X2, int send,
			     struct context *c)
{

	PRINTF("X1: %d\n", X1);
	PRINTF("X2: %d\n", X2);

	BYTE_ARRAY_NEW(input1, MAX_NONCE_LEN + 1, MAX_NONCE_LEN + 1); 
	BYTE_ARRAY_NEW(input1_enc, AS_BSTR_SIZE(MAX_NONCE_LEN + 1), AS_BSTR_SIZE(MAX_NONCE_LEN + 1));

	if (N1->len > 0){

		// ---- input1 = X1 || N1 ----
		input1.ptr[0] = X1;              
		memcpy(&input1.ptr[1], N1->ptr, N1->len);
		input1.len = 1 + N1->len;

		PRINT_ARRAY("input1 to encode:", input1.ptr, input1.len);

		encode_bstr(&input1, &input1_enc);
	}
	else {
		// Empty input2 byte string
		input1_enc.ptr[0] = 0x40;
		input1_enc.len = 1;
	}
	PRINT_ARRAY("Input_1 encoded:", input1_enc.ptr, input1_enc.len);

	BYTE_ARRAY_NEW(input2, MAX_NONCE_LEN + 1, MAX_NONCE_LEN + 1); 
	BYTE_ARRAY_NEW(input2_enc, AS_BSTR_SIZE(MAX_NONCE_LEN + 1), AS_BSTR_SIZE(MAX_NONCE_LEN + 1));

	if (N2->len > 0){

		// ---- input2 = X2 || N2 ----
		input2.ptr[0] = X2;                
		memcpy(&input2.ptr[1], N2->ptr, N2->len);
		input2.len = 1 + N2->len;

		PRINT_ARRAY("input2 to encode:", input2.ptr, input2.len);

		encode_bstr(&input2, &input2_enc);
	}
	else {
		// Empty input2 byte string
		input2_enc.ptr[0] = 0x40;
		input2_enc.len = 1;
	}
	PRINT_ARRAY("Input_2 encoded:", input2_enc.ptr, input2_enc.len);

	// --- Concatenate in lexicographic order ---
	BYTE_ARRAY_NEW(X_N, input1_enc.len + input2_enc.len, input1_enc.len + input2_enc.len);

	if (is_lexicographically_shorter(&input1_enc, &input2_enc)) {
	    memcpy(X_N.ptr, input1_enc.ptr, input1_enc.len);
	    memcpy(X_N.ptr + input1_enc.len, input2_enc.ptr, input2_enc.len);
	} else {
	    memcpy(X_N.ptr, input2_enc.ptr, input2_enc.len);
	    memcpy(X_N.ptr + input2_enc.len, input1_enc.ptr, input1_enc.len);
	}
	PRINT_ARRAY("X_N:", X_N.ptr, X_N.len);

	// Persist CTX_OLD to be used later in CTX_NEW derivation.
	if (c->cc.master_secret_old.len == 0){
		c->cc.master_secret_old.len = sizeof(c->cc.master_secret_old_buf);
		c->cc.master_secret_old.ptr = c->cc.master_secret_old_buf;
		byte_array_cpy(&(c->cc.master_secret_old), &(c->cc.master_secret), c->cc.master_secret.len);
		PRINT_ARRAY("old OSCORE Master Secret:", c->cc.master_secret_old.ptr, c->cc.master_secret_old.len);
	}

	c->cc.master_salt.len = sizeof(c->cc.new_master_salt_buf);
	c->cc.master_salt.ptr = c->cc.new_master_salt_buf;
	uint32_t salt_len = input1_enc.len + input2_enc.len;

	byte_array_cpy(&(c->cc.master_salt), &X_N, salt_len);
	PRINT_ARRAY("new OSCORE Master Salt:", c->cc.master_salt.ptr, c->cc.master_salt.len);

	c->cc.master_secret.len = sizeof(c->cc.new_master_secret_buf);
	c->cc.master_secret.ptr = c->cc.new_master_secret_buf;
	memset(c->cc.master_secret.ptr, 0, 16);
	PRINT_ARRAY("c->cc.master_secret:", c->cc.master_secret.ptr, c->cc.master_secret.len);

	//PRINT_ARRAY("old OSCORE Master Secret:", c->cc.master_secret_old.ptr, c->cc.master_secret_old.len);

	kudos_kdf(SHA_256, &(c->cc.master_secret_old), "oscore key update", &X_N, &(c->cc.master_secret));
	PRINT_ARRAY("new OSCORE Master Secret:", c->cc.master_secret.ptr, c->cc.master_secret.len);

	//Updating also Common_IV
	TRY(derive_common_iv(&c->cc));

	TRY(server_replay_window_reinit( 0, &(c->rc.replay_window)));

	TRY(derive_recipient_key(&(c->cc), &(c->rc)));
	TRY(derive_sender_key(&(c->cc), &(c->sc)));

	//Storing the nonces.
	if (send){
		c->rrc.kudos_nonce_1.len = sizeof(c->rrc.kudos_nonce_1_buf);
		c->rrc.kudos_nonce_1.ptr = c->rrc.kudos_nonce_1_buf;
		byte_array_cpy(&(c->rrc.kudos_nonce_1), N1, NONCE_LEN);
		PRINT_ARRAY("KUDOS N1", c->rrc.kudos_nonce_1.ptr, c->rrc.kudos_nonce_1.len);

		c->rrc.kudos_x1 = X1;
	} else {
		c->rrc.kudos_nonce_2.len = sizeof(c->rrc.kudos_nonce_2_buf);
		c->rrc.kudos_nonce_2.ptr = c->rrc.kudos_nonce_2_buf;
		byte_array_cpy(&(c->rrc.kudos_nonce_2), N2, NONCE_LEN);
		PRINT_ARRAY("KUDOS N2", c->rrc.kudos_nonce_2.ptr, c->rrc.kudos_nonce_2.len);

		c->rrc.kudos_x2 = X2;
	}
	return ok;

}

enum err check_context_freshness(struct context *c)
{
	if (NULL == c) {
		return wrong_parameter;
	}

	/* "If the Sender Sequence Number exceeds the maximum, the endpoint MUST NOT
	   process any more messages with the given Sender Context."
	   For more info, refer to RFC 8613 p. 7.2.1. */
	if (c->sc.ssn >= OSCORE_SSN_OVERFLOW_VALUE) {
		PRINT_MSG(
			"Sender Sequence Number reached its limit. New security context must be established.\n");
		return oscore_ssn_overflow;
	}
	return ok;
}

enum err ssn2piv(uint64_t ssn, struct byte_array *piv)
{
	if ((NULL == piv) || (NULL == piv->ptr) ||
	    (ssn > MAX_PIV_FIELD_VALUE)) {
		return wrong_parameter;
	}

	static uint8_t tmp_piv[MAX_PIV_LEN];
	uint8_t len = 0;
	while (ssn > 0) {
		tmp_piv[len] = (uint8_t)(ssn & 0xFF);
		len++;
		ssn >>= 8;
	}

	if (len == 0) {
		//if the sender seq number is 0 piv has value 0 and length 1
		piv->ptr[0] = 0;
		piv->len = 1;
	} else {
		//PIV is encoded in big endian
		for (uint8_t pos = 0; pos < len; pos++) {
			piv->ptr[pos] = tmp_piv[len - 1 - pos];
		}
		piv->len = len;
	}
	return ok;
}

enum err piv2ssn(struct byte_array *piv, uint64_t *ssn)
{
	if ((NULL == ssn) || (NULL == piv)) {
		return wrong_parameter;
	}

	uint8_t *value = piv->ptr;
	uint32_t len = piv->len;
	if (len > MAX_PIV_LEN) {
		return wrong_parameter;
	}

	uint64_t result = 0;
	if (NULL != value) {
		//PIV is encoded in big endian
		for (uint32_t pos = 0; pos < len; pos++) {
			result += (uint64_t)(value[pos])
				  << (8 * (len - 1 - pos));
		}
	}
	*ssn = result;
	return ok;
}
