#include "transfers.h"

#include <string.h>
#include <assert.h>
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

static const TX_OBJECT DEFAULT_TX = {
        {0},       ZERO_HASH, 0,        ZERO_TAG, 0, 0, 0,       ZERO_HASH,
        ZERO_HASH, ZERO_HASH, ZERO_TAG, 0,        0, 0, ZERO_TAG};

static char *int64_to_chars(int64_t value, char *chars, unsigned int num_trytes)
{
    trit_t trits[num_trytes * 3];
    int64_to_trits(value, trits, num_trytes * 3);
    trits_to_chars(trits, chars, num_trytes * 3);

    return chars + num_trytes;
}

static void get_address(const unsigned char *seed_bytes, uint32_t idx,
                        unsigned int security, char *address)
{
    unsigned char bytes[48];
    get_public_addr(seed_bytes, idx, security, bytes);
    bytes_to_chars(bytes, address, 48);
}

static char *char_copy(char *destination, const char *source, unsigned int len)
{
    assert(strnlen(source, len) == len);
    memmove(destination, source, len);

    return destination + len;
}

static char *char_add(char *destination, const char c, unsigned int len)
{
    memset(destination, c, len);
    return destination + len;
}

static void get_transaction_chars_with_signature(
    const char *signatureMessageFragment, const char *address, int64_t value,
    const char *tag, uint32_t timestamp, uint32_t currentIndex,
    uint32_t lastIndex, const char *bundle, char *transaction_chars)
{
    char *c = transaction_chars;

    c = char_copy(c, signatureMessageFragment, 2187);
    c = char_copy(c, address, 81);
    c = int64_to_chars(value, c, 27);
    c = char_copy(c, tag, 27); // obsoleteTag
    c = int64_to_chars(timestamp, c, 9);
    c = int64_to_chars(currentIndex, c, 9);
    c = int64_to_chars(lastIndex, c, 9);
    c = char_copy(c, bundle, 81);
    c = char_add(c, '9', 81); // trunkTransaction
    c = char_add(c, '9', 81); // branchTransaction
    c = char_copy(c, tag, 27);
    c = char_add(c, '9', 9);  // attachmentTimestamp
    c = char_add(c, '9', 9);  // attachmentTimestampLowerBound
    c = char_add(c, '9', 9);  // attachmentTimestampUpperBound
    c = char_add(c, '9', 27); // nonce

    assert(strnlen(transaction_chars, 2673) == 2673);
}

static void get_transaction_chars(const char *address, int64_t value,
                                  const char *tag, uint32_t timestamp,
                                  uint32_t currentIndex, uint32_t lastIndex,
                                  const char *bundle, char *transaction_chars)
{
    // fill the empty signature fragment in place
    char *signatureMessageFragment = transaction_chars;
    char_add(signatureMessageFragment, '9', 2187);

    get_transaction_chars_with_signature(signatureMessageFragment, address,
                                         value, tag, timestamp, currentIndex,
                                         lastIndex, bundle, transaction_chars);
}

static void increment_obsolete_tag(unsigned int tag_increment, TX_OUTPUT *tx)
{
    char extended_tag[81];
    unsigned char tag_bytes[48];
    rpad_chars(extended_tag, tx->tag, NUM_HASH_TRYTES);
    chars_to_bytes(extended_tag, tag_bytes, NUM_HASH_TRYTES);

    bytes_add_u32_mem(tag_bytes, tag_increment);
    bytes_to_chars(tag_bytes, extended_tag, 48);

    memcpy(tx->tag, extended_tag, 27);
}

TX_OBJECT tx_object_buffer = {};

void clear_tx_buffer(void){
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

void prepare_transfers_light(char *seed, uint8_t security, TX_OUTPUT *outputs,
                             unsigned int num_outputs, TX_INPUT *inputs, unsigned int num_inputs,
                             tx_receiver_t tx_receiver_func, bundle_hash_receiver bundle_receiver_func){
    // TODO use a proper timestamp
    const uint32_t timestamp = 0;
    const unsigned int num_txs = num_outputs + num_inputs * security;
    const unsigned int last_tx_index = num_txs - 1;

    unsigned char seed_bytes[48];
    chars_to_bytes(seed, seed_bytes, 81);


    // create a secure bundle
    BUNDLE_CTX bundle_ctx;
    bundle_initialize(&bundle_ctx, last_tx_index);

    // OUTPUT TX OBJECTS
    int idx = 0;
    for (unsigned int i = 0; i < num_outputs; i++) {

        clear_tx_buffer();
        // initialize with defaults
        memcpy(&tx_object_buffer, &DEFAULT_TX, sizeof(TX_OBJECT));

        rpad_chars(tx_object_buffer.signatureMessageFragment, outputs[i].message, 2187);
        memcpy(tx_object_buffer.address, outputs[i].address, 81);
        tx_object_buffer.value = outputs[i].value;
        rpad_chars(tx_object_buffer.obsoleteTag, outputs[i].tag, 27);
        tx_object_buffer.timestamp = timestamp;
        tx_object_buffer.currentIndex = (uint32_t)idx;
        tx_object_buffer.lastIndex = last_tx_index;
        rpad_chars(tx_object_buffer.tag, outputs[i].tag, 27);

        // Bundle
        bundle_set_external_address(&bundle_ctx, tx_object_buffer.address);
        //Todo: Really tag not obsolete tag?
        bundle_add_tx(&bundle_ctx, tx_object_buffer.value, tx_object_buffer.tag, tx_object_buffer.timestamp);

        if(tx_receiver_func(&tx_object_buffer)){
            idx++;
            continue;
        }else{
            break;
        }
    }

    // INPUT TX_OBJECTS
    for (unsigned int i = 0; i < num_inputs; i++) {

        clear_tx_buffer();
        // initialize with defaults
        memcpy(&tx_object_buffer, &DEFAULT_TX, sizeof(TX_OBJECT));

        char *address = tx_object_buffer.address;
        get_address(seed_bytes, inputs[i].key_index, security, address);
        tx_object_buffer.value = -inputs[i].balance;
        tx_object_buffer.timestamp = timestamp;
        tx_object_buffer.currentIndex = idx;
        tx_object_buffer.lastIndex = last_tx_index;
        idx++;

        tx_receiver_func(&tx_object_buffer);


        // Bundle
        bundle_set_external_address(&bundle_ctx, tx_object_buffer.address);
        //Todo: Really tag not obsolete tag?
        bundle_add_tx(&bundle_ctx, tx_object_buffer.value, tx_object_buffer.tag, tx_object_buffer.timestamp);

        // add meta transactions, signature
        for (unsigned int j = 1; j < security; j++) {

            clear_tx_buffer();
            // initialize with defaults
            memcpy(&tx_object_buffer, &DEFAULT_TX, sizeof(TX_OBJECT));

            memcpy(tx_object_buffer.address, address, 81);
            tx_object_buffer.value = 0;
            tx_object_buffer.timestamp = timestamp;
            tx_object_buffer.currentIndex = idx;
            tx_object_buffer.lastIndex = last_tx_index;

            // Bundle
            bundle_set_external_address(&bundle_ctx, tx_object_buffer.address);
            //Todo: Really tag not obsolete tag?
            bundle_add_tx(&bundle_ctx, tx_object_buffer.value, tx_object_buffer.tag, tx_object_buffer.timestamp);


            if(tx_receiver_func(&tx_object_buffer)){
                idx++;
                continue;
            }else{
                break;
            }
        }
    }

    uint32_t tag_increment = bundle_finalize(&bundle_ctx);
    increment_obsolete_tag(tag_increment, &tx_object_buffer);

    // sign the inputs
    tryte_t normalized_bundle_hash[81];
    bundle_get_normalized_hash(&bundle_ctx, normalized_bundle_hash);

    for (unsigned int i = 0; i < num_inputs; i++) {
        clear_tx_buffer();

        SIGNING_CTX signing_ctx;
        signing_initialize(&signing_ctx, seed_bytes, inputs[i].key_index,
                           security, normalized_bundle_hash);

        // Why outputs and not inputs?
        unsigned int idx = num_outputs + i * security;

        // exactly one fragment for transaction including meta transactions
        for (unsigned int j = 0; j < security; j++) {

            unsigned char signature_bytes[27 * 48];
            signing_next_fragment(&signing_ctx, signature_bytes);
            bytes_to_chars(signature_bytes, tx_object_buffer.signatureMessageFragment,
                           27 * 48);


            if(tx_receiver_func(&tx_object_buffer)){
                idx++;
                continue;
            }else{
                break;
            }
        }
    }

    char bundle_hash[81];
    bytes_to_chars(bundle_ctx.hash, bundle_hash, 48);
    // send the bundle hash to the receiver func
    bundle_receiver_func(bundle_hash);
}

void prepare_transfers(const char *seed, uint8_t security, TX_OUTPUT *outputs,
                       int num_outputs, TX_INPUT *inputs, int num_inputs,
                       char transaction_chars[][2673])
{
    // TODO use a proper timestamp
    const uint32_t timestamp = 0;
    const unsigned int num_txs = num_outputs + num_inputs * security;
    const unsigned int last_tx_index = num_txs - 1;

    unsigned char seed_bytes[48];
    chars_to_bytes(seed, seed_bytes, 81);

    // create a secure bundle
    BUNDLE_CTX bundle_ctx;
    bundle_initialize(&bundle_ctx, last_tx_index);

    // add the outputs first
    for (unsigned int i = 0; i < (unsigned int) num_outputs; i++) {
        bundle_set_external_address(&bundle_ctx, outputs[i].address);

        // assure that the tag is 27 chars
        rpad_chars(outputs[i].tag, outputs[i].tag, 27);
        bundle_add_tx(&bundle_ctx, outputs[i].value, outputs[i].tag, timestamp);
    }

    // temporarily store the input addresses
    char input_addresses[num_inputs][81];

    for (unsigned int i = 0; i < (unsigned int) num_inputs; i++) {
        get_address(seed_bytes, inputs[i].key_index, security,
                    input_addresses[i]);
        bundle_set_internal_address(&bundle_ctx, input_addresses[i],
                                    inputs[i].key_index);

        bundle_add_tx(&bundle_ctx, -inputs[i].balance, ZERO_TAG, timestamp);

        // add meta transactions
        for (unsigned int j = 1; j < security; j++) {
            bundle_set_internal_address(&bundle_ctx, input_addresses[i],
                                        inputs[i].key_index);
            bundle_add_tx(&bundle_ctx, 0, ZERO_TAG, timestamp);
        }
    }

    // increment the tag in the first output object
    uint32_t tag_increment = bundle_finalize(&bundle_ctx);
    increment_obsolete_tag(tag_increment, &outputs[0]);

    // compute the bundle hash in base-27
    char bundle[81];
    bytes_to_chars(bundle_get_hash(&bundle_ctx), bundle, 48);

    // create transaction chars
    unsigned int idx = 0;
    for (unsigned int i = 0; i < (unsigned int) num_outputs; i++) {
        get_transaction_chars(outputs[i].address, outputs[i].value,
                              outputs[i].tag, timestamp, idx, last_tx_index,
                              bundle, transaction_chars[last_tx_index - idx]);
        idx++;
    }

    // sign the inputs
    tryte_t normalized_bundle_hash[81];
    bundle_get_normalized_hash(&bundle_ctx, normalized_bundle_hash);

    for (unsigned int i = 0; i < (unsigned int) num_inputs; i++) {
        SIGNING_CTX signing_ctx;
        signing_initialize(&signing_ctx, seed_bytes, inputs[i].key_index,
                           security, normalized_bundle_hash);

        // exactly one fragment for transaction including meta transactions
        for (unsigned int j = 0; j < security; j++) {

            // use the transaction in place to store the signature fragment
            char *signatureMessageFragment =
                transaction_chars[last_tx_index - idx];

            unsigned char signature_bytes[27 * 48];
            signing_next_fragment(&signing_ctx, signature_bytes);
            bytes_to_chars(signature_bytes, signatureMessageFragment, 27 * 48);

            const int64_t value = j == 0 ? -inputs[i].balance : 0;
            get_transaction_chars_with_signature(
                signatureMessageFragment, input_addresses[i], value, ZERO_TAG,
                timestamp, idx, last_tx_index, bundle,
                transaction_chars[last_tx_index - idx]);
            idx++;
        }
    }
}
