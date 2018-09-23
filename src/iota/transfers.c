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

static char *int64_to_chars(int64_t value, char *chars, unsigned int num_trytes)
{
    trit_t trits[num_trytes * 3];
    int64_to_trits(value, trits, num_trytes * 3);
    trits_to_chars(trits, chars, num_trytes * 3);

    return chars + num_trytes;
}

unsigned char trytes_bytes_buffer[48];

int clear_tryte_bytes(void){
    for(int i = 0; i < 48; i ++){
        trytes_bytes_buffer[i] = 0;
    }

    return 1;
}

void iota_wallet_get_address(char * seed, uint32_t idx, unsigned int security, char *address)
{
    unsigned char seed_bytes[48];
    chars_to_bytes(seed, seed_bytes, 81);
    clear_tryte_bytes();
    get_public_addr(seed_bytes, idx, security, trytes_bytes_buffer);
    bytes_to_chars(trytes_bytes_buffer, address, 48);
}

static char *char_copy(char *destination, const char *source, unsigned int len)
{
    assert(strnlen(source, len) == len);
    memmove(destination, source, len);

    return destination + len;
}

static void increment_obsolete_tag(unsigned int tag_increment, iota_wallet_tx_output_t *tx)
{
    char extended_tag[81];
    unsigned char tag_bytes[48];
    rpad_chars(extended_tag, tx->tag, NUM_HASH_TRYTES);
    chars_to_bytes(extended_tag, tag_bytes, NUM_HASH_TRYTES);

    bytes_add_u32_mem(tag_bytes, tag_increment);
    bytes_to_chars(tag_bytes, extended_tag, 48);

    memcpy(tx->tag, extended_tag, 27);
}

void clear_transaction_char_buffer(char * buffer){
    for(int i = 0; i < 2672; i++){
        buffer[i] = 0;
    }
}

void iota_wallet_construct_raw_transaction_chars(char * buffer, char * bundle_hash, iota_wallet_tx_object_t * tx){
    clear_transaction_char_buffer(buffer);
    buffer[2673] = '\0';
    char *c = buffer;

    c = char_copy(c, tx->signatureMessageFragment, 2187);
    c = char_copy(c, tx->address, 81);
    c = int64_to_chars(tx->value, c, 27);
    c = char_copy(c, tx->tag, 27);
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

iota_wallet_tx_object_t tx_object_buffer = {};

void clear_tx_object_buffer(void){
    char_copy(tx_object_buffer.address, ZERO_HASH, 81);
    char_copy(tx_object_buffer.branchTransaction, ZERO_HASH, 81);
    char_copy(tx_object_buffer.trunkTransaction, ZERO_HASH, 81);
    char_copy(tx_object_buffer.bundle, ZERO_HASH, 81);
    char_copy(tx_object_buffer.nonce, ZERO_TAG, 27);
    char_copy(tx_object_buffer.tag, ZERO_TAG, 27);
    char_copy(tx_object_buffer.obsoleteTag, ZERO_TAG, 27);

    tx_object_buffer.timestamp = 0;
    tx_object_buffer.value = 0;


    for(unsigned int i = 0; i < 2187; i++){
        tx_object_buffer.signatureMessageFragment[i] = '9';
    }
}

void clear_tx_signature_bytes_buffer(void){
    for(unsigned int i = 0; i < 2187; i++){
        tx_object_buffer.signatureMessageFragment[i] = '9';
    }
}


iota_wallet_tx_receiver_t tx_receiver_func;
void iota_wallet_set_tx_receiver_func(iota_wallet_tx_receiver_t func){
    tx_receiver_func = func;
}

iota_wallet_bundle_hash_receiver_ptr_t bundle_hash_receiver_func;
void iota_wallet_set_bundle_hash_receiver_func(iota_wallet_bundle_hash_receiver_ptr_t func){
    bundle_hash_receiver_func = func;
}

unsigned char seed_bytes_buffer[48];
void clear_seed_bytes_buffer(void){
    for(int i = 0; i < 48; i++){
        seed_bytes_buffer[i] = 0;
    }
}

tryte_t normalized_bundle_hash_buffer[81];
void clear_normalized_bundle_hash_buffer(void){
    for(int i = 0; i < 81; i++){
        normalized_bundle_hash_buffer[i] = '9';
    }
}


unsigned char signature_bytes_buffer[27 * 48];
void clear_signature_bytes_buffer(void){
    for(int i = 0; i < 27 * 48; i++){
        signature_bytes_buffer[i] = 0;
    }
}

// create a secure bundle
BUNDLE_CTX bundle_ctx_buffer;
void clear_bundle_ctx_buffer(void){
    bundle_ctx_buffer.last_index = 0;
    bundle_ctx_buffer.current_index = 0;

    for(int i = 0; i < 768; i++){
        if(i < 8){
            bundle_ctx_buffer.values[i] = 0;
            bundle_ctx_buffer.indices[i] = 0;
        }
        if(i < 48){
            bundle_ctx_buffer.hash[i] = 0;
        }

        bundle_ctx_buffer.bytes[i] = 0;
    }
}

void construct_bundle(iota_wallet_bundle_object_t bundle_object){
    clear_bundle_ctx_buffer();
    clear_normalized_bundle_hash_buffer();

    uint8_t security = bundle_object.security;
    iota_wallet_tx_output_t *outputs = bundle_object.output_txs;
    unsigned int num_outputs = bundle_object.output_txs_length;
    iota_wallet_tx_input_t *inputs = bundle_object.input_txs;
    unsigned int num_inputs = bundle_object.input_txs_length;
    uint32_t timestamp = bundle_object.timestamp;

    const unsigned int num_txs = num_outputs + num_inputs * security;
    const unsigned int last_tx_index = num_txs - 1;

    bundle_initialize(&bundle_ctx_buffer, last_tx_index);

    // add the outputs first
    for (unsigned int i = 0; i < num_outputs; i++) {
        bundle_set_external_address(&bundle_ctx_buffer, outputs[i].address);

        // assure that the tag is 27 chars
        rpad_chars(outputs[i].tag, outputs[i].tag, 27);
        bundle_add_tx(&bundle_ctx_buffer, outputs[i].value, outputs[i].tag, timestamp);
    }


    //INPUT TX
    for (unsigned int i = 0; i < num_inputs; i++) {
        bundle_set_internal_address(&bundle_ctx_buffer, inputs[i].address,
                                    inputs[i].key_index);

        bundle_add_tx(&bundle_ctx_buffer, -inputs[i].balance, ZERO_TAG, timestamp);

        // add signature transaction
        for (unsigned int j = 1; j < security; j++) {
            bundle_set_internal_address(&bundle_ctx_buffer, inputs[i].address,
                                        inputs[i].key_index);
            bundle_add_tx(&bundle_ctx_buffer, 0, ZERO_TAG, timestamp);
        }
    }

    uint32_t tag_increment = bundle_finalize(&bundle_ctx_buffer);
    increment_obsolete_tag(tag_increment, &outputs[0]);

    char bundle_hash[81];
    bytes_to_chars(bundle_get_hash(&bundle_ctx_buffer), bundle_hash, 48);

    // send the bundle hash to the bundle receiver ptr func
    bundle_hash_receiver_func(bundle_hash);

    bundle_get_normalized_hash(&bundle_ctx_buffer, normalized_bundle_hash_buffer);
}

SIGNING_CTX signing_ctx_buffer;
void clear_signing_ctx_buffer(void){
    signing_ctx_buffer.fragment_index = 0;
    signing_ctx_buffer.last_fragment = 0;
    for(int i = 0; i < 81; i++){
        if(i < 48){
            signing_ctx_buffer.state[i] = 0;
        }
        signing_ctx_buffer.hash[i] = '9';
    }
}

void iota_wallet_create_tx_bundle(iota_wallet_bundle_object_t bundle_object){
    clear_seed_bytes_buffer();

    char *seed = bundle_object.seed;
    uint8_t security = bundle_object.security;
    iota_wallet_tx_output_t *outputs = bundle_object.output_txs;
    unsigned int num_outputs = bundle_object.output_txs_length;
    iota_wallet_tx_input_t *inputs = bundle_object.input_txs;
    unsigned int num_inputs = bundle_object.input_txs_length;

    chars_to_bytes(seed, seed_bytes_buffer, 81);

    construct_bundle(bundle_object);

    const uint32_t timestamp = bundle_object.timestamp;
    const unsigned int num_txs = num_outputs + num_inputs * security;
    const unsigned int num_txs_without_security = num_outputs + num_inputs;
    const unsigned int last_tx_index = num_txs - 1;
    const unsigned int last_without_security_tx_index = num_txs_without_security - 1;

    // OUTPUT TX OBJECTS
    int idx = 0;
    for (unsigned int i = 0; i < num_outputs; i++) {
        clear_tx_object_buffer();

        rpad_chars(tx_object_buffer.signatureMessageFragment, outputs[i].message, 2187);
        memcpy(tx_object_buffer.address, outputs[i].address, 81);
        tx_object_buffer.value = outputs[i].value;
        rpad_chars(tx_object_buffer.obsoleteTag, outputs[i].tag, 27);
        tx_object_buffer.timestamp = timestamp;
        tx_object_buffer.currentIndex = (uint32_t)idx;
        tx_object_buffer.lastIndex = last_tx_index;
        rpad_chars(tx_object_buffer.tag, outputs[i].tag, 27);

        if(tx_receiver_func(&tx_object_buffer)){
            idx++;
            continue;
        }else{
            break;
        }
    }

    // INPUT TX_OBJECTS
    for (unsigned int i = 0; i < num_inputs; i++) {
        clear_tx_object_buffer();
        clear_signing_ctx_buffer();

        signing_initialize(&signing_ctx_buffer, seed_bytes_buffer, inputs[i].key_index,
                           security, normalized_bundle_hash_buffer);

        tx_object_buffer.value = -inputs[i].balance;
        tx_object_buffer.timestamp = timestamp;
        tx_object_buffer.currentIndex = (uint32_t) idx;
        tx_object_buffer.lastIndex = last_tx_index;
        char_copy(tx_object_buffer.address, inputs[i].address, 81);


        // add bundle signature
        for (unsigned int j = 0; j < security; j++) {
            clear_tx_signature_bytes_buffer();
            // Because the first segment is in the input tx itself.
            if(j > 0){
                char_copy(tx_object_buffer.address, inputs[i].address, 81);
                tx_object_buffer.value = 0;
                tx_object_buffer.timestamp = timestamp;
                tx_object_buffer.currentIndex = last_without_security_tx_index + j;
                tx_object_buffer.lastIndex = last_tx_index;
            }

            clear_signature_bytes_buffer();

            signing_next_fragment(&signing_ctx_buffer, signature_bytes_buffer);
            bytes_to_chars(signature_bytes_buffer, tx_object_buffer.signatureMessageFragment,
                           27 * 48);

            if(tx_receiver_func(&tx_object_buffer)){
                idx++;
                clear_tx_object_buffer();
                continue;
            }else{
                break;
            }
        }
    }
}
