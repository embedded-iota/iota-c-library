#ifndef TRANSFERS_H
#define TRANSFERS_H

#include <stdint.h>
#include "iota_types.h"

typedef enum {
    BUNDLE_CREATION_SUCCESS,
    BUNDLE_CREATION_BUNDLE_RECEIVER_ERROR,
    BUNDLE_CREATION_TRANSACTION_RECEIVER_ERROR
} iota_wallet_status_codes_t;

typedef struct {
    char signatureMessageFragment[2187];
    char address[NUM_ADDR_TRYTES];
    int64_t value;
    char obsoleteTag[NUM_TAG_TRYTES];
    char tag[NUM_TAG_TRYTES];
    uint32_t timestamp;
    uint32_t currentIndex;
    uint32_t lastIndex;
} iota_wallet_tx_object_t;

typedef struct {
        char address[NUM_ADDR_TRYTES];
        int64_t value;
        char tag[NUM_TAG_TRYTES];
} iota_wallet_tx_output_t;

typedef struct {
    char address[NUM_ADDR_TRYTES];
    char message[2187];
    char tag[NUM_TAG_TRYTES];
} iota_wallet_tx_zero_t;

typedef struct {
        int64_t value;
        char address[NUM_ADDR_TRYTES];
        uint32_t key_index;
} iota_wallet_tx_input_t;

typedef struct {
    char seed[81];
    uint8_t security;
    iota_wallet_tx_output_t * output_txs;
    uint32_t output_txs_length;
    iota_wallet_tx_zero_t * zero_txs;
    uint32_t zero_txs_length;
    iota_wallet_tx_input_t * input_txs;
    uint32_t input_txs_length;
    iota_wallet_tx_output_t * change_tx;
    uint32_t timestamp;
} iota_wallet_bundle_description_t;

/**
 * @brief type for callback tx_object receiver. Called each time input tx or output tx is computed.
 */
typedef int (*iota_wallet_tx_receiver_ptr_t)(iota_wallet_tx_object_t * tx_object);

/**
 * @brief type for callback receiver. Called when bundle_hash is computed.
 */
typedef int (*iota_wallet_bundle_hash_receiver_ptr_t)(char * hash);

/**
 * @brief initializes the iota wallet. Init of mutexes. Need to be called once.
 */
void iota_wallet_init(void);

/**
 *
 * @param seed Seed chars where the address is generated from.
 * @param idx the address index
 * @param security
 * @param address the pointer which receives the address
 */
void iota_wallet_get_address(char * seed, uint32_t idx, unsigned int security, char *address);

/**
 *
 * @brief Creates a IOTA transaction bundle by given input & output txs
 * within the bundle_description
 * @param bundle_hash_receiver_ptr Pointer function which receives the bundle hash.
 * @param tx_receiver_ptr Pointer function which receives every tx_object within the bundle
 * @param bundle_desciption
 * @return iota_wallet_status_codes_t
 */
iota_wallet_status_codes_t iota_wallet_create_tx_bundle(
        iota_wallet_bundle_hash_receiver_ptr_t bundle_hash_receiver_ptr,
        iota_wallet_tx_receiver_ptr_t tx_receiver_ptr,
        iota_wallet_bundle_description_t * bundle_desciption);

/**
 *
 * @param buffer the raw transaction char buffer. Size = 2674. Last byte = '\0'
 * @param bundle_hash
 * @param tx the transaction to construct the raw transaction data from.
 */
void iota_wallet_construct_raw_transaction_chars(
        char * buffer, char * bundle_hash, iota_wallet_tx_object_t * tx);

#endif //TRANSFERS_H
