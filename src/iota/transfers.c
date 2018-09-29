#include "transfers.h"

#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
// iota-related stuff
#include "conversion.h"
#include "addresses.h"
#include "bundle.h"
#include "signing.h"
#include "../aux.h"

#define ZERO_HASH                                                              \
    "999999999999999999999999999999999999999999999999999999999999999999999999" \
    "999999999"
#define ZERO_TAG "999999999999999999999999999"

static char *int64_to_chars(int64_t value, char *chars, unsigned int num_trytes) {
    trit_t trits[num_trytes * 3];
    int64_to_trits(value, trits, num_trytes * 3);
    trits_to_chars(trits, chars, num_trytes * 3);

    return chars + num_trytes;
}

/**
 *
 * @param seed Seed chars where the address is generated from.
 * @param idx the address index
 * @param security
 * @param address the pointer which receives the address
 */
void iota_wallet_get_address(char seed[81], uint32_t idx, unsigned int security, char address[81]) {
    unsigned char trytes_bytes_buffer[48];
    unsigned char seed_bytes[48];
    chars_to_bytes(seed, seed_bytes, 81);
    get_public_addr(seed_bytes, idx, security, trytes_bytes_buffer);
    bytes_to_chars(trytes_bytes_buffer, address, 48);
}

static char *char_copy(char *destination, const char *source, unsigned int len) {
    assert(strnlen(source, len) == len);
    memmove(destination, source, len);

    return destination + len;
}

/**
 * @brief M (13) bug tag increment.
 * @param tag_increment
 * @param tx the transaction where the tag will get incremented
 */
static void increment_obsolete_tag(unsigned int tag_increment, iota_wallet_tx_output_t *tx) {
    char extended_tag[81];
    unsigned char tag_bytes[48];
    rpad_chars(extended_tag, tx->tag, NUM_HASH_TRYTES);
    chars_to_bytes(extended_tag, tag_bytes, NUM_HASH_TRYTES);

    bytes_add_u32_mem(tag_bytes, tag_increment);
    bytes_to_chars(tag_bytes, extended_tag, 48);

    memcpy(tx->tag, extended_tag, 27);
}

void clear_transaction_char_buffer(char *buffer) {
    memset(buffer, 0, 2672);
}

/**
 *
 * @param buffer the raw transaction char buffer. Size = 2674. Last byte = '\0'
 * @param bundle_hash
 * @param tx the transaction to construct the raw transaction data from.
 */
void iota_wallet_construct_raw_transaction_chars(char * buffer, char *bundle_hash,
                                                 iota_wallet_tx_object_t *tx) {
    clear_transaction_char_buffer(buffer);
    buffer[2673] = '\0';
    char *c = buffer;

    c = char_copy(c, tx->signatureMessageFragment, 2187);
    c = char_copy(c, tx->address, 81);
    c = int64_to_chars(tx->value, c, 27);
    c = char_copy(c, tx->obsoleteTag, 27);
    c = int64_to_chars(tx->timestamp, c, 9);
    c = int64_to_chars(tx->currentIndex, c, 9);
    c = int64_to_chars(tx->lastIndex, c, 9);
    c = char_copy(c, bundle_hash, 81);
    c = char_copy(c, ZERO_HASH, 81);
    c = char_copy(c, ZERO_HASH, 81);
    c = char_copy(c, tx->tag, 27);
    c = int64_to_chars((int64_t) 0, c, 9);
    c = int64_to_chars((int64_t) 0, c, 9);
    c = int64_to_chars((int64_t) 0, c, 9);
    char_copy(c, tx->nonce, 27);
}

/**
 *
 * @param tx_object
 */
void clear_tx_object_buffer(iota_wallet_tx_object_t *tx_object) {
    memset(tx_object->address, '9', 81);
    memset(tx_object->branchTransaction, '9', 81);
    memset(tx_object->trunkTransaction, '9', 81);
    memset(tx_object->bundle, '9', 81);
    memset(tx_object->nonce, '9', 27);
    memset(tx_object->tag, '9', 27);
    memset(tx_object->obsoleteTag, '9', 27);
    memset(tx_object->signatureMessageFragment, '9', 2187);

    tx_object->timestamp = 0;
    tx_object->value = 0;
}

/**
 *
 * @param ctx
 * @param security
 * @param timestamp
 * @param input
 */
void add_input_tx_to_bundle(
        BUNDLE_CTX *ctx, uint8_t security, uint32_t timestamp, iota_wallet_tx_input_t *input) {

    bundle_set_internal_address(ctx, input->address, input->key_index);
    bundle_add_tx(ctx, -input->value, ZERO_TAG, timestamp);

    // add signature transaction
    for (unsigned int j = 1; j < security; j++) {
        bundle_set_internal_address(ctx, input->address, input->key_index);
        bundle_add_tx(ctx, 0, ZERO_TAG, timestamp);
    }
}

/**
 *
 * @param ctx
 * @param timestamp
 * @param output
 */
void add_output_tx_to_bundle(BUNDLE_CTX *ctx, uint32_t timestamp, iota_wallet_tx_output_t *output) {

    bundle_set_external_address(ctx, output->address);
    // assure that the tag is 27 chars
    rpad_chars(output->tag, output->tag, 27);
    bundle_add_tx(ctx, output->value, output->tag, timestamp);
}

void normalize_bundle_hash(
        tryte_t normalized_bundle_hash_ptr[81],
        BUNDLE_CTX *bundle_ctx, uint32_t tag_increment, iota_wallet_tx_output_t *increment_output) {

    increment_obsolete_tag(tag_increment, increment_output);
    bundle_get_normalized_hash(bundle_ctx, normalized_bundle_hash_ptr);
}

/**
 * @brief Constructs the bundle ctx for generating the bundle hash
 * @param bundle_ctx
 * @param normalized_bundle_hash_ptr
 * @param bundle_object_ptr
 * @param bundle_hash_reveicer
 */
void construct_bundle(
        BUNDLE_CTX *bundle_ctx, tryte_t normalized_bundle_hash_ptr[81],
        iota_wallet_bundle_description_t *bundle_object_ptr) {

    uint8_t security = bundle_object_ptr->security;
    iota_wallet_tx_output_t *outputs = bundle_object_ptr->output_txs;
    unsigned int num_outputs = bundle_object_ptr->output_txs_length;
    iota_wallet_tx_input_t *inputs = bundle_object_ptr->input_txs;
    unsigned int num_inputs = bundle_object_ptr->input_txs_length;
    uint32_t timestamp = bundle_object_ptr->timestamp;

    const unsigned int num_txs = num_outputs + num_inputs * security;
    const unsigned int last_tx_index = num_txs - 1;

    bundle_initialize(bundle_ctx, last_tx_index);

    for (unsigned int i = 0; i < num_outputs; i++) {
        add_output_tx_to_bundle(bundle_ctx, timestamp, &outputs[i]);
    }

    for (unsigned int i = 0; i < num_inputs; i++) {
        add_input_tx_to_bundle(bundle_ctx, security, timestamp, &inputs[i]);
    }

    uint32_t tag_increment = bundle_finalize(bundle_ctx);
    normalize_bundle_hash(normalized_bundle_hash_ptr, bundle_ctx, tag_increment, &outputs[0]);
}

/**
 *
 * @param tx_object the receiving object
 * @param output the output tx to copy from
 * @param index the txs index position within the bundle
 * @param last_index the last index of the bundle
 * @param timestamp
 */
void cpy_output_tx_to_tx_object(
        iota_wallet_tx_object_t *tx_object, iota_wallet_tx_output_t *output,
        uint32_t index, uint32_t last_index, uint32_t timestamp) {

    rpad_chars(tx_object->signatureMessageFragment, output->message, 2187);
    memcpy(tx_object->address, output->address, 81);
    tx_object->value = output->value;
    rpad_chars(tx_object->obsoleteTag, output->tag, 27);
    tx_object->timestamp = timestamp;
    tx_object->currentIndex = index;
    tx_object->lastIndex = last_index;
    rpad_chars(tx_object->tag, output->tag, 27);
}

/**
 *
 * @param signing_ctx
 * @param tx_object The current tx_object of the input transaction in the bundle
 * @param security
 * @param zero_tx_start_index Index where start to add signature fragments (zero tx)
 * @return The next empty tx slot index for the next signature segment
 */
uint32_t construct_singature_for_input_tx(
        iota_wallet_tx_receiver_ptr_t tx_receiver_ptr,
        SIGNING_CTX *signing_ctx,
        iota_wallet_tx_object_t *tx_object,
        uint8_t security,
        uint32_t zero_tx_start_index) {

    uint32_t tx_index = tx_object->currentIndex;
    for (unsigned int i = 0; i < security; i++) {
        unsigned char signature_bytes[27 * 48];

        // Because the first signature segment is in the input tx itself.
        if (i > 0) {
            tx_object->value = 0;
            tx_object->currentIndex = zero_tx_start_index + i;
            tx_index = tx_object->currentIndex;
        }

        signing_next_fragment(signing_ctx, signature_bytes);
        bytes_to_chars(signature_bytes, tx_object->signatureMessageFragment, 27 * 48);

        if (tx_receiver_ptr(tx_object)) {
            memset(tx_object->signatureMessageFragment, '9', 2187);
            continue;
        } else {
            break;
        }
    }

    return tx_index + 1;
}

/**
 *
 * @param bundle_hash_receiver_ptr Pointer function which receives the bundle hash.
 * @param tx_receiver_ptr Pointer function which receives every tx_object within the bundle
 * @param bundle_desciption
 */
void iota_wallet_create_tx_bundle(iota_wallet_bundle_hash_receiver_ptr_t bundle_hash_receiver_ptr,
                                  iota_wallet_tx_receiver_ptr_t tx_receiver_ptr,
                                  iota_wallet_bundle_description_t *bundle_desciption) {

    unsigned char seed_bytes[48];
    iota_wallet_tx_object_t tx_object = {};

    char *seed_chars = bundle_desciption->seed;
    uint8_t security = bundle_desciption->security;
    iota_wallet_tx_output_t *outputs = bundle_desciption->output_txs;
    unsigned int num_outputs = bundle_desciption->output_txs_length;
    iota_wallet_tx_input_t *inputs = bundle_desciption->input_txs;
    unsigned int num_inputs = bundle_desciption->input_txs_length;

    chars_to_bytes(seed_chars, seed_bytes, 81);

    tryte_t normalized_bundle_hash_ptr[81];
    BUNDLE_CTX bundle_ctx;
    construct_bundle(&bundle_ctx, normalized_bundle_hash_ptr, bundle_desciption);

    char bundle_hash[81];
    bytes_to_chars(bundle_get_hash(&bundle_ctx), bundle_hash, 48);
    // send the bundle hash to the bundle receiver ptr func
    bundle_hash_receiver_ptr(bundle_hash);

    const uint32_t timestamp = bundle_desciption->timestamp;
    const unsigned int num_txs = num_outputs + num_inputs * security;
    const unsigned int num_txs_without_security = num_outputs + num_inputs;
    const unsigned int last_tx_index = num_txs - 1;
    const unsigned int last_without_security_tx_index = num_txs_without_security - 1;

    // OUTPUT TX OBJECTS
    int idx = 0;
    for (unsigned int i = 0; i < num_outputs; i++) {
        clear_tx_object_buffer(&tx_object);

        cpy_output_tx_to_tx_object(
                &tx_object, &outputs[i], (uint32_t) idx, last_tx_index, timestamp);

        if (tx_receiver_ptr(&tx_object)) {
            idx++;
            continue;
        } else {
            break;
        }
    }

    // INPUT TX_OBJECTS
    uint32_t next_signature_segment_index = last_without_security_tx_index;
    for (unsigned int i = 0; i < num_inputs; i++) {
        clear_tx_object_buffer(&tx_object);

        SIGNING_CTX signing_ctx;
        signing_initialize(&signing_ctx, seed_bytes, inputs[i].key_index, security,
                           normalized_bundle_hash_ptr);

        tx_object.value = -inputs[i].value;
        tx_object.timestamp = timestamp;
        tx_object.currentIndex = (uint32_t) idx;
        tx_object.lastIndex = last_tx_index;
        char_copy(tx_object.address, inputs[i].address, 81);

        next_signature_segment_index = construct_singature_for_input_tx(
                tx_receiver_ptr, &signing_ctx, &tx_object, security,
                next_signature_segment_index);

    }

}
