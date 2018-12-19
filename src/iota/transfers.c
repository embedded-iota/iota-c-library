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

static pthread_mutex_t iota_lib_tx_mutex = {};
static pthread_mutexattr_t iota_lib_tx_mutex_attr = {};

static pthread_mutex_t iota_lib_address_mutex = {};
static pthread_mutexattr_t iota_lib_input_address_mutex_attr = {};

static pthread_mutex_t iota_lib_bundle_hash_mutex = {};
static pthread_mutexattr_t iota_lib_bundle_hash_mutex_attr = {};

static pthread_mutex_t iota_lib_normalized_bundle_hash_mutex = {};
static pthread_mutexattr_t iota_lib_normalized_bundle_hash_mutex_attr = {};

static pthread_mutex_t iota_lib_signature_mutex = {};
static pthread_mutexattr_t iota_lib_signature_mutex_attr = {};

/**
 *
 * @param value the source value
 * @param chars destination ptr
 * @param num_trytes number of trytes
 * @return ptr position of the end of tryte chars ptr
 */
static char *int64_to_chars(int64_t value, char *chars, unsigned int num_trytes) {
    trit_t trits[num_trytes * 3];
    int64_to_trits(value, trits, num_trytes * 3);
    trits_to_chars(trits, chars, num_trytes * 3);

    return chars + num_trytes;
}

void iota_lib_get_address(char seed[81], uint32_t idx, unsigned int security, char address[81]) {
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
 * @param tx the transaction where the tag will get incremented
 */
static void increment_obsolete_tag(unsigned int tag_increment, iota_lib_tx_output_t *tx) {
    char extended_tag[81];
    unsigned char tag_bytes[48];
    rpad_chars(extended_tag, tx->tag, NUM_HASH_TRYTES);
    chars_to_bytes(extended_tag, tag_bytes, NUM_HASH_TRYTES);

    bytes_add_u32_mem(tag_bytes, tag_increment);
    bytes_to_chars(tag_bytes, extended_tag, 48);

    memcpy(tx->tag, extended_tag, 27);
}

static void clear_transaction_char_buffer(char *buffer) {
    memset(buffer, 0, 2672);
}

void iota_lib_construct_raw_transaction_chars(char * buffer, char *bundle_hash,
                                                 iota_lib_tx_object_t *tx) {
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
    c = int64_to_chars((int64_t) 0, c, 9);
    c = int64_to_chars((int64_t) 0, c, 9);
    c = int64_to_chars((int64_t) 0, c, 9);
}

/**
 *
 * @param tx_object
 */
static void clear_tx_object_buffer(iota_lib_tx_object_t *tx_object) {
    memset(tx_object->address, '9', 81);
    memset(tx_object->obsoleteTag, '9', 27);
    memset(tx_object->signatureMessageFragment, '9', 2187);

    tx_object->timestamp = 0;
    tx_object->value = 0;
}

/**
 *
 * @param tx_object
 */
static void clear_input_address_buffer(char address[81]) {
    memset(address, '9', 81);
}

/**
 *
 * @param ctx
 * @param security
 * @param timestamp
 * @param input
 */
static void add_input_tx_to_bundle(
        BUNDLE_CTX *ctx, uint8_t security, uint32_t timestamp, iota_lib_tx_input_t *input) {

    bundle_set_internal_address(ctx, input->address, input->seed_address_index);
    bundle_add_tx(ctx, -input->value, ZERO_TAG, timestamp);

    // add signature transaction
    for (unsigned int j = 1; j < security; j++) {
        bundle_set_internal_address(ctx, input->address, input->seed_address_index);
        bundle_add_tx(ctx, 0, ZERO_TAG, timestamp);
    }
}

/**
 *
 * @param ctx
 * @param timestamp
 * @param output
 */
static void add_output_tx_to_bundle(BUNDLE_CTX *ctx, uint32_t timestamp, iota_lib_tx_output_t *output) {

    bundle_set_external_address(ctx, output->address);
    // assure that the tag is 27 chars
    rpad_chars(output->tag, output->tag, 27);
    bundle_add_tx(ctx, output->value, output->tag, timestamp);
}

static void normalize_bundle_hash(
        tryte_t normalized_bundle_hash_ptr[81],
        BUNDLE_CTX *bundle_ctx, uint32_t tag_increment, iota_lib_tx_output_t *increment_output) {

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
static void construct_bundle(
        BUNDLE_CTX *bundle_ctx, tryte_t normalized_bundle_hash_ptr[81],
        iota_lib_bundle_description_t *bundle_object_ptr) {

    uint8_t security = bundle_object_ptr->security;
    iota_lib_tx_output_t *outputs = bundle_object_ptr->output_txs;
    unsigned int num_outputs = bundle_object_ptr->output_txs_length;
    iota_lib_tx_input_t *inputs = bundle_object_ptr->input_txs;
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
static void cpy_output_tx_to_tx_object(
        iota_lib_tx_object_t *tx_object, iota_lib_tx_output_t *output,
        uint32_t index, uint32_t last_index, uint32_t timestamp) {

    memcpy(tx_object->address, output->address, 81);
    tx_object->value = output->value;
    rpad_chars(tx_object->obsoleteTag, output->tag, 27);
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
        iota_lib_tx_object_t *tx_object, iota_lib_tx_zero_t *zero,
        uint32_t index, uint32_t last_index, uint32_t timestamp) {

    rpad_chars(tx_object->signatureMessageFragment, zero->message, 2187);
    memcpy(tx_object->address, zero->address, 81);
    tx_object->value = 0;
    rpad_chars(tx_object->obsoleteTag, zero->tag, 27);
    tx_object->timestamp = timestamp;
    tx_object->currentIndex = index;
    tx_object->lastIndex = last_index;
}

unsigned char signature_bytes[1296];
static void clear_signature_bytes(unsigned char signature_bytes[1296]){
    memset(signature_bytes, 0, 1296);
}

/**
 *
 * @param signing_ctx
 * @param tx_object The current tx_object of the input transaction in the bundle
 * @param security
 * @param zero_tx_start_index Index where start to add signature fragments (zero tx)
 * @return The next empty tx slot index for the next signature segment. Returns 0 at receiver error.
 */
static uint32_t construct_singature_for_input_tx(
        iota_lib_tx_receiver_ptr_t tx_receiver_ptr,
        SIGNING_CTX *signing_ctx,
        iota_lib_tx_object_t *tx_object,
        uint8_t security,
        uint32_t zero_tx_start_index) {

    uint32_t tx_index = tx_object->currentIndex;
    for (unsigned int i = 0; i < security; i++) {


        // Because the first signature segment is in the input tx itself.
        if (i > 0) {
            pthread_mutex_lock(&iota_lib_tx_mutex);
            tx_object->value = 0;
            tx_object->currentIndex = zero_tx_start_index + i;
            tx_index = tx_object->currentIndex;
        }

        pthread_mutex_lock(&iota_lib_signature_mutex);
        clear_signature_bytes(signature_bytes);
        signing_next_fragment(signing_ctx, signature_bytes);
        bytes_to_chars(signature_bytes, tx_object->signatureMessageFragment, 1296);

        if (tx_receiver_ptr(tx_object)) {
            pthread_mutex_unlock(&iota_lib_signature_mutex);
            pthread_mutex_unlock(&iota_lib_tx_mutex);
            memset(tx_object->signatureMessageFragment, '9', 2187);
        } else {
            pthread_mutex_unlock(&iota_lib_signature_mutex);
            pthread_mutex_unlock(&iota_lib_tx_mutex);
            return 0;
        }
    }

    return tx_index + 1;
}

static iota_lib_tx_object_t tx_object = {};

char address_buffer[81] = {0};

void iota_lib_init(void){
    pthread_mutex_init(&iota_lib_tx_mutex, &iota_lib_tx_mutex_attr);
    pthread_mutex_init(&iota_lib_address_mutex, &iota_lib_input_address_mutex_attr);
    pthread_mutex_init(&iota_lib_bundle_hash_mutex, &iota_lib_bundle_hash_mutex_attr);
    pthread_mutex_init(
            &iota_lib_normalized_bundle_hash_mutex, &iota_lib_normalized_bundle_hash_mutex_attr);
    pthread_mutex_init(&iota_lib_signature_mutex, &iota_lib_signature_mutex_attr);

    bundle_mutex_init();
    conversion_mutex_init();
}

void generate_addresses_for_inputs(
        char *seed_chars, unsigned int security,
        iota_lib_tx_input_t *inputs, unsigned int num_inputs){
    pthread_mutex_lock(&iota_lib_address_mutex);
    for(unsigned int i = 0; i < num_inputs; i++){
        clear_input_address_buffer(address_buffer);

        iota_lib_tx_input_t * current_input = &inputs[i];
        uint32_t address_index = current_input->seed_address_index;

        iota_lib_get_address(seed_chars, address_index, security, address_buffer);
        memcpy(current_input->address, address_buffer, 81);
    }
    pthread_mutex_unlock(&iota_lib_address_mutex);
}

char bundle_hash[81] = {0};

void clear_bundle_hash(char bundle_hash[81]){
    memset(bundle_hash, '\0', 81);
}

tryte_t normalized_bundle_hash_ptr[81] = {0};
void clear_normalized_bundle_hash(tryte_t normalized_bundle_hash_ptr[81]){
    memset(normalized_bundle_hash_ptr, '\0', 81);
}

iota_lib_status_codes_t iota_lib_create_tx_bundle(
        iota_lib_bundle_hash_receiver_ptr_t bundle_hash_receiver_ptr,
        iota_lib_tx_receiver_ptr_t tx_receiver_ptr,
        iota_lib_bundle_description_t *bundle_desciption) {

    char *seed_chars = bundle_desciption->seed;
    uint8_t security = bundle_desciption->security;
    iota_lib_tx_output_t *outputs = bundle_desciption->output_txs;
    unsigned int num_outputs = bundle_desciption->output_txs_length;
    iota_lib_tx_zero_t *zeros = bundle_desciption->zero_txs;
    unsigned int num_zeros = bundle_desciption->zero_txs_length;
    iota_lib_tx_input_t *inputs = bundle_desciption->input_txs;
    unsigned int num_inputs = bundle_desciption->input_txs_length;

    generate_addresses_for_inputs(seed_chars, (unsigned int)security, inputs, num_inputs);

    pthread_mutex_lock(&iota_lib_normalized_bundle_hash_mutex);
    pthread_mutex_lock(&iota_lib_bundle_hash_mutex);
    clear_bundle_hash(bundle_hash);
    clear_normalized_bundle_hash(normalized_bundle_hash_ptr);

    BUNDLE_CTX bundle_ctx;
    construct_bundle(&bundle_ctx, normalized_bundle_hash_ptr, bundle_desciption);
    bytes_to_chars(bundle_get_hash(&bundle_ctx), bundle_hash, 48);

    if(!bundle_hash_receiver_ptr(bundle_hash)){
        return BUNDLE_CREATION_BUNDLE_RECEIVER_ERROR;
    }
    pthread_mutex_unlock(&iota_lib_bundle_hash_mutex);

    const uint32_t timestamp = bundle_desciption->timestamp;
    const unsigned int num_output_and_zero_tx = num_outputs + num_zeros;
    const unsigned int num_txs = num_outputs + num_zeros + num_inputs * security;
    const unsigned int num_txs_without_security = num_outputs + num_zeros + num_inputs;
    const unsigned int last_tx_index = num_txs - 1;
    const unsigned int last_without_security_tx_index = num_txs_without_security - 1;


    // INPUT TX_OBJECTS
    /**
     * Do input tx first, so that the iota_lib_normalized_bundle_hash_mutex can
     * be unlocked as early as possible. The transactions are not sorted anymore.
     */
    int input_id = num_output_and_zero_tx;
    uint32_t next_signature_segment_index = last_without_security_tx_index;
    unsigned char seed_bytes[48];
    chars_to_bytes(seed_chars, seed_bytes, 81);
    for (unsigned int i = 0; i < num_inputs; i++) {
        pthread_mutex_lock(&iota_lib_tx_mutex);
        clear_tx_object_buffer(&tx_object);

        SIGNING_CTX signing_ctx;
        signing_initialize(&signing_ctx, seed_bytes, inputs[i].seed_address_index, security,
                           normalized_bundle_hash_ptr);

        tx_object.value = -inputs[i].value;
        tx_object.timestamp = timestamp;
        tx_object.currentIndex = (uint32_t) input_id;
        tx_object.lastIndex = last_tx_index;
        char_copy(tx_object.address, inputs[i].address, 81);

        next_signature_segment_index = construct_singature_for_input_tx(
                tx_receiver_ptr, &signing_ctx, &tx_object, security,
                next_signature_segment_index);

        if(next_signature_segment_index == 0){
            return BUNDLE_CREATION_TRANSACTION_RECEIVER_ERROR;
        }
    }

    pthread_mutex_unlock(&iota_lib_normalized_bundle_hash_mutex);

    // OUTPUT TX OBJECTS
    int idx = 0;
    for (unsigned int i = 0; i < num_outputs; i++) {
        pthread_mutex_lock(&iota_lib_tx_mutex);

        clear_tx_object_buffer(&tx_object);

        cpy_output_tx_to_tx_object(
                &tx_object, &outputs[i], (uint32_t) idx, last_tx_index, timestamp);

        if (tx_receiver_ptr(&tx_object)) {
            idx++;
            pthread_mutex_unlock(&iota_lib_tx_mutex);
        } else {
            pthread_mutex_unlock(&iota_lib_tx_mutex);
            return BUNDLE_CREATION_TRANSACTION_RECEIVER_ERROR;
        }
    }

    // ZERO TX OBJECTS
    for (unsigned int i = 0; i < num_zeros; i++) {
        pthread_mutex_lock(&iota_lib_tx_mutex);

        clear_tx_object_buffer(&tx_object);

        cpy_zero_tx_to_tx_object(
                &tx_object, &zeros[i], (uint32_t) idx, last_tx_index, timestamp);

        if (tx_receiver_ptr(&tx_object)){
            idx++;
            pthread_mutex_unlock(&iota_lib_tx_mutex);
        } else {
            pthread_mutex_unlock(&iota_lib_tx_mutex);
            return BUNDLE_CREATION_TRANSACTION_RECEIVER_ERROR;
        }
    }



    return BUNDLE_CREATION_SUCCESS;
}
