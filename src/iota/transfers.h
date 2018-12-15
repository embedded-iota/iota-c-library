#ifndef TRANSFERS_H
#define TRANSFERS_H

#include <stdint.h>
#include <stdbool.h>
#include "iota_types.h"

typedef enum {
    BUNDLE_CREATION_SUCCESS,
    BUNDLE_CREATION_BUNDLE_RECEIVER_ERROR,
    BUNDLE_CREATION_TRANSACTION_RECEIVER_ERROR
} iota_lib_status_codes_t;

typedef struct {
    char signatureMessageFragment[2187];
    char address[81];
    int64_t value;
    char obsoleteTag[27];
    char tag[27];
    uint32_t timestamp;
    uint32_t currentIndex;
    uint32_t lastIndex;
} iota_lib_tx_object_t;

typedef struct {
        char address[81];
        int64_t value;
        char tag[27];
} iota_lib_tx_output_t;

typedef struct {
    char address[81];
    char message[2187];
    char tag[27];
} iota_lib_tx_zero_t;

typedef struct {
        int64_t value;
        char address[81];
        uint32_t key_index;
} iota_lib_tx_input_t;

typedef struct {
    char seed[81];
    uint8_t security;
    iota_lib_tx_output_t * output_txs;
    uint32_t output_txs_length;
    iota_lib_tx_zero_t * zero_txs;
    uint32_t zero_txs_length;
    iota_lib_tx_input_t * input_txs;
    uint32_t input_txs_length;
    uint32_t timestamp;
} iota_lib_bundle_description_t;

/**
 * @brief type for callback tx_object receiver. Called each time input tx or output tx is computed.
 */
typedef bool (*iota_lib_tx_receiver_ptr_t)(iota_lib_tx_object_t * tx_object);

/**
 * @brief type for callback receiver. Called when bundle_hash is computed.
 */
typedef bool (*iota_lib_bundle_hash_receiver_ptr_t)(char * hash);

/**
 * @brief initializes the iota wallet. Init of mutexes. Need to be called once.
 */
void iota_lib_init(void);

/**
 *
 * @param seed Seed chars where the address is generated from.
 * @param idx the address index
 * @param security
 * @param address the pointer which receives the address
 */
void iota_lib_get_address(char * seed, uint32_t idx, unsigned int security, char *address);

/**
 *
 * @brief Creates a IOTA transaction bundle by given input & output txs
 * within the bundle_description
 * @param bundle_hash_receiver_ptr Pointer function which receives the bundle hash.
 * @param tx_receiver_ptr Pointer function which receives every tx_object within the bundle
 * @param bundle_desciption
 * @return iota_lib_status_codes_t
 */
iota_lib_status_codes_t iota_lib_create_tx_bundle(
        iota_lib_bundle_hash_receiver_ptr_t bundle_hash_receiver_ptr,
        iota_lib_tx_receiver_ptr_t tx_receiver_ptr,
        iota_lib_bundle_description_t * bundle_desciption);

/**
 *
 * @param buffer the raw transaction char buffer. Size = 2674. Last byte = '\0'
 * @param bundle_hash
 * @param tx the transaction to construct the raw transaction data from.
 */
void iota_lib_construct_raw_transaction_chars(
        char * buffer, char * bundle_hash, iota_lib_tx_object_t * tx);

#endif //TRANSFERS_H
