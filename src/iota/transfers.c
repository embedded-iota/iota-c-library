// Std library
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdint.h>

// iota-related stuff
#include "transfers.h"
#include "conversion.h"
#include "addresses.h"
#include "bundle.h"
#include "signing.h"
#include "../aux.h"
#include "common.h"

//POSIX
#include "pthread.h"

#define ZERO_TAG "999999999999999999999999999"

void iota_wallet_get_address(char seed[81], uint32_t idx, unsigned int security, char address[81]) {
    unsigned char trytes_bytes_buffer[48];
    unsigned char seed_bytes[48];
    chars_to_bytes(seed, seed_bytes, 81);
    get_public_addr(seed_bytes, idx, security, trytes_bytes_buffer);
    bytes_to_chars(trytes_bytes_buffer, address, 48);
}

static char *char_copy(char *destination, const char *source, unsigned int len) {
    assert(common_strnlen(source, len) == len);
    memmove(destination, source, len);

    return destination + len;
}

/**
 * @brief M (13) bug tag increment.
 * @param tag_increment
 * @param tag the tag to be incremented
 */
static void increment_obsolete_tag(unsigned int tag_increment, char *tag) {
    char extended_tag[81];
    unsigned char tag_bytes[48];
    rpad_chars(extended_tag, tag, NUM_TAG_TRYTES);
    memset(extended_tag + NUM_TAG_TRYTES, '9',
        NUM_HASH_TRYTES - NUM_TAG_TRYTES);
    chars_to_bytes(extended_tag, tag_bytes, NUM_HASH_TRYTES);

    bytes_add_u32_mem(tag_bytes, tag_increment);
    bytes_to_chars(tag_bytes, extended_tag, 48);

    memcpy(tag, extended_tag, 27);
}

static void clear_transaction_char_buffer(char *buffer) {
    memset(buffer, '9', NUM_TRANSACTION_TRYTES);
}

void iota_wallet_construct_raw_transaction_chars(char * buffer, char *bundle_hash,
                                                 iota_wallet_tx_object_t *tx) {
    clear_transaction_char_buffer(buffer);
    char *c = buffer;

    c = char_copy(c, tx->signatureMessageFragment, NUM_SIG_MSG_TRYTES);
    c = char_copy(c, tx->address, NUM_ADDR_TRYTES);
    c = int64_to_chars(tx->value, c, 27);
    c = char_copy(c, tx->obsoleteTag, NUM_TAG_TRYTES);
    c = int64_to_chars(tx->timestamp, c, 9);
    c = int64_to_chars(tx->currentIndex, c, 9);
    c = int64_to_chars(tx->lastIndex, c, 9);
    c = char_copy(c, bundle_hash, NUM_HASH_TRYTES);
    c += NUM_HASH_TRYTES + NUM_HASH_TRYTES;	/* skip trunk and branch */
    c = char_copy(c, tx->tag, NUM_TAG_TRYTES);
}

/**
 *
 * @param tx_object
 */
static void clear_tx_object_buffer(iota_wallet_tx_object_t *tx_object) {
    memset(tx_object->address, '9', NUM_ADDR_TRYTES);
    memset(tx_object->obsoleteTag, '9', NUM_TAG_TRYTES);
    memset(tx_object->tag, '9', NUM_TAG_TRYTES);
    memset(tx_object->signatureMessageFragment, '9', NUM_SIG_MSG_TRYTES);

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
static void add_input_tx_to_bundle(
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
static void add_output_tx_to_bundle(BUNDLE_CTX *ctx, uint32_t timestamp, iota_wallet_tx_output_t *output) {

    bundle_set_external_address(ctx, output->address);
    // assure that the tag is 27 chars
    rpad_chars(output->tag, output->tag, NUM_TAG_TRYTES);
    bundle_add_tx(ctx, output->value, output->tag, timestamp);
}

/**
 *
 * @param ctx
 * @param timestamp
 * @param zero_tx
 */
static void add_zero_tx_to_bundle(BUNDLE_CTX *ctx, uint32_t timestamp,
        iota_wallet_tx_zero_t *zero_tx) {
    bundle_set_external_address(ctx, zero_tx->address);
    rpad_chars(zero_tx->tag, zero_tx->tag, NUM_TAG_TRYTES);
    bundle_add_tx(ctx, 0, zero_tx->tag, timestamp);
}

static void normalize_bundle_hash(
        tryte_t normalized_bundle_hash_ptr[NUM_HASH_TRYTES],
        BUNDLE_CTX *bundle_ctx, uint32_t tag_increment, char *tag) {

    increment_obsolete_tag(tag_increment, tag);
    bundle_get_normalized_hash(bundle_ctx, normalized_bundle_hash_ptr);
}

/**
 * @brief Constructs the bundle ctx for generating the bundle hash
 * @param bundle_ctx
 * @param normalized_bundle_hash_ptr
 * @param bundle_object_ptr
 * @param bundle_hash_reveicer
 */
static void construct_bundle(
        BUNDLE_CTX *bundle_ctx,
        tryte_t normalized_bundle_hash_ptr[NUM_HASH_TRYTES],
        iota_wallet_bundle_description_t *bundle_object_ptr) {

    uint8_t security = bundle_object_ptr->security;
    iota_wallet_tx_output_t *outputs = bundle_object_ptr->output_txs;
    unsigned int num_outputs = bundle_object_ptr->output_txs_length;
    iota_wallet_tx_zero_t *zeros = bundle_object_ptr->zero_txs;
    unsigned int num_zeros = bundle_object_ptr->zero_txs_length;
    iota_wallet_tx_input_t *inputs = bundle_object_ptr->input_txs;
    unsigned int num_inputs = bundle_object_ptr->input_txs_length;
    uint32_t timestamp = bundle_object_ptr->timestamp;
    char *tag = (num_outputs ? outputs[0].tag : zeros[0].tag);

    const unsigned int num_txs = num_outputs + num_zeros + num_inputs * security
            + !!bundle_object_ptr->change_tx;
    const unsigned int last_tx_index = num_txs - 1;

    bundle_initialize(bundle_ctx, last_tx_index);

    for (unsigned int i = 0; i < num_outputs; i++) {
        add_output_tx_to_bundle(bundle_ctx, timestamp, &outputs[i]);
    }

    for (unsigned int i = 0; i < num_zeros; i++) {
        add_zero_tx_to_bundle(bundle_ctx, timestamp, &zeros[i]);
    }

    for (unsigned int i = 0; i < num_inputs; i++) {
        add_input_tx_to_bundle(bundle_ctx, security, timestamp, &inputs[i]);
    }

    if (bundle_object_ptr->change_tx != NULL) {
        add_output_tx_to_bundle(bundle_ctx, timestamp,
                bundle_object_ptr->change_tx);
    }

    uint32_t tag_increment = bundle_finalize(bundle_ctx);
    normalize_bundle_hash(normalized_bundle_hash_ptr, bundle_ctx, tag_increment,
            tag);
}

/**
 *
 * @param tx_object the receiving object
 * @param output the output tx to copy from
 * @param index the txs index position within the bundle
 * @param last_index the last index of the bundle
 * @param timestamp
 */
static void cpy_output_tx_to_tx_object(
        iota_wallet_tx_object_t *tx_object, iota_wallet_tx_output_t *output,
        uint32_t index, uint32_t last_index, uint32_t timestamp) {

    memcpy(tx_object->address, output->address, NUM_ADDR_TRYTES);
    tx_object->value = output->value;
    rpad_chars(tx_object->obsoleteTag, output->tag, NUM_TAG_TRYTES);
    rpad_chars(tx_object->tag, output->tag, NUM_TAG_TRYTES);
    tx_object->timestamp = timestamp;
    tx_object->currentIndex = index;
    tx_object->lastIndex = last_index;
}

/**
 *
 * @param tx_object the receiving object
 * @param zero the zero tx to copy from
 * @param index the txs index position within the bundle
 * @param last_index the last index of the bundle
 * @param timestamp
 */
static void cpy_zero_tx_to_tx_object(
        iota_wallet_tx_object_t *tx_object, iota_wallet_tx_zero_t *zero,
        uint32_t index, uint32_t last_index, uint32_t timestamp) {

    rpad_chars(tx_object->signatureMessageFragment, zero->message,
            NUM_SIG_MSG_TRYTES);
    memcpy(tx_object->address, zero->address, NUM_ADDR_TRYTES);
    tx_object->value = 0;
    rpad_chars(tx_object->obsoleteTag, zero->tag, NUM_TAG_TRYTES);
    rpad_chars(tx_object->tag, zero->tag, NUM_TAG_TRYTES);
    tx_object->timestamp = timestamp;
    tx_object->currentIndex = index;
    tx_object->lastIndex = last_index;
}

static pthread_mutex_t iota_wallet_tx_mutex;

/**
 *
 * @param signing_ctx
 * @param tx_object The current tx_object of the input transaction in the bundle
 * @param security
 * @param zero_tx_start_index Index where start to add signature fragments (zero tx)
 * @return The next empty tx slot index for the next signature segment. Returns 0 at receiver error.
 */
static uint32_t construct_singature_for_input_tx(
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
            pthread_mutex_lock(&iota_wallet_tx_mutex);
            tx_object->value = 0;
            tx_object->currentIndex = zero_tx_start_index + i;
            tx_index = tx_object->currentIndex;
        }

        signing_next_fragment(signing_ctx, signature_bytes);
        bytes_to_chars(signature_bytes, tx_object->signatureMessageFragment, 27 * 48);

        if (tx_receiver_ptr(tx_object)) {
            pthread_mutex_unlock(&iota_wallet_tx_mutex);
            memset(tx_object->signatureMessageFragment, '9',
                    NUM_SIG_MSG_TRYTES);
        } else {
            pthread_mutex_unlock(&iota_wallet_tx_mutex);
            return 0;
        }
    }

    return tx_index + 1;
}

static iota_wallet_tx_object_t tx_object = {};

void iota_wallet_init(void){
    pthread_mutex_init(&iota_wallet_tx_mutex, NULL);

    bundle_mutex_init();
    conversion_mutex_init();
}


iota_wallet_status_codes_t iota_wallet_create_tx_bundle(
        iota_wallet_bundle_hash_receiver_ptr_t bundle_hash_receiver_ptr,
        iota_wallet_tx_receiver_ptr_t tx_receiver_ptr,
        iota_wallet_bundle_description_t *bundle_desciption) {

    char *seed_chars = bundle_desciption->seed;
    uint8_t security = bundle_desciption->security;
    iota_wallet_tx_output_t *outputs = bundle_desciption->output_txs;
    unsigned int num_outputs = bundle_desciption->output_txs_length;
    iota_wallet_tx_zero_t *zeros = bundle_desciption->zero_txs;
    unsigned int num_zeros = bundle_desciption->zero_txs_length;
    iota_wallet_tx_input_t *inputs = bundle_desciption->input_txs;
    unsigned int num_inputs = bundle_desciption->input_txs_length;

    char bundle_hash[NUM_HASH_TRYTES];
    tryte_t normalized_bundle_hash_ptr[NUM_HASH_TRYTES];
    BUNDLE_CTX bundle_ctx;
    if ((num_outputs == 0) && (num_zeros == 0)) {
        return BUNDLE_CREATION_INVALID;
    }
    construct_bundle(&bundle_ctx, normalized_bundle_hash_ptr, bundle_desciption);
    bytes_to_chars(bundle_get_hash(&bundle_ctx), bundle_hash, NUM_HASH_BYTES);

    if(!bundle_hash_receiver_ptr(bundle_hash)){
        return BUNDLE_CREATION_BUNDLE_RECEIVER_ERROR;
    }

    const uint32_t timestamp = bundle_desciption->timestamp;
    const unsigned int num_txs = num_outputs + num_zeros + num_inputs * security
            + !!bundle_desciption->change_tx;
    const unsigned int num_txs_without_security = num_outputs + num_zeros + num_inputs;
    const unsigned int last_tx_index = num_txs - 1;
    const unsigned int last_without_security_tx_index = num_txs_without_security - 1;

    // OUTPUT TX OBJECTS
    int idx = 0;
    for (unsigned int i = 0; i < num_outputs; i++) {
        pthread_mutex_lock(&iota_wallet_tx_mutex);

        clear_tx_object_buffer(&tx_object);

        cpy_output_tx_to_tx_object(
                &tx_object, &outputs[i], (uint32_t) idx, last_tx_index, timestamp);

        if (tx_receiver_ptr(&tx_object)) {
            idx++;
            pthread_mutex_unlock(&iota_wallet_tx_mutex);
        } else {
            pthread_mutex_unlock(&iota_wallet_tx_mutex);
            return BUNDLE_CREATION_TRANSACTION_RECEIVER_ERROR;
        }
    }

    // ZERO TX OBJECTS
    for (unsigned int i = 0; i < num_zeros; i++) {
        pthread_mutex_lock(&iota_wallet_tx_mutex);

        clear_tx_object_buffer(&tx_object);

        cpy_zero_tx_to_tx_object(
                &tx_object, &zeros[i], (uint32_t) idx, last_tx_index, timestamp);

        if (tx_receiver_ptr(&tx_object)){
            idx++;
            pthread_mutex_unlock(&iota_wallet_tx_mutex);
        } else {
            pthread_mutex_unlock(&iota_wallet_tx_mutex);
            return BUNDLE_CREATION_TRANSACTION_RECEIVER_ERROR;
        }
    }

    // INPUT TX_OBJECTS
    uint32_t next_signature_segment_index = last_without_security_tx_index;
    unsigned char seed_bytes[48];
    chars_to_bytes(seed_chars, seed_bytes, 81);
    for (unsigned int i = 0; i < num_inputs; i++) {
        pthread_mutex_lock(&iota_wallet_tx_mutex);
        clear_tx_object_buffer(&tx_object);

        SIGNING_CTX signing_ctx;
        signing_initialize(&signing_ctx, seed_bytes, inputs[i].key_index, security,
                           normalized_bundle_hash_ptr);

        tx_object.value = -inputs[i].value;
        tx_object.timestamp = timestamp;
        tx_object.currentIndex = (uint32_t) idx;
        tx_object.lastIndex = last_tx_index;
        char_copy(tx_object.address, inputs[i].address, NUM_ADDR_TRYTES);

        next_signature_segment_index = construct_singature_for_input_tx(
                tx_receiver_ptr, &signing_ctx, &tx_object, security,
                next_signature_segment_index);

        if(next_signature_segment_index == 0){
            return BUNDLE_CREATION_TRANSACTION_RECEIVER_ERROR;
        }
        idx++;
    }

    // CHANGE TX OBJECT
    if (bundle_desciption->change_tx != NULL) {
        pthread_mutex_lock(&iota_wallet_tx_mutex);

        clear_tx_object_buffer(&tx_object);

        cpy_output_tx_to_tx_object(
                &tx_object, bundle_desciption->change_tx, last_tx_index,
                last_tx_index, timestamp);

        if (tx_receiver_ptr(&tx_object)) {
            pthread_mutex_unlock(&iota_wallet_tx_mutex);
        } else {
            pthread_mutex_unlock(&iota_wallet_tx_mutex);
            return BUNDLE_CREATION_TRANSACTION_RECEIVER_ERROR;
        }
    }

    return BUNDLE_CREATION_SUCCESS;
}
