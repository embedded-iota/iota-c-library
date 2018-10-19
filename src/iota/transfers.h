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
    char address[81];
    int64_t value;
    char obsoleteTag[27];
    uint32_t timestamp;
    uint32_t currentIndex;
    uint32_t lastIndex;
} iota_wallet_tx_object_t;

typedef struct {
        char address[81];
        int64_t value;
        char message[2187];
        char tag[27];
} iota_wallet_tx_output_t;

typedef struct {
        int64_t value;
        char address[81];
        uint32_t key_index;
} iota_wallet_tx_input_t;

typedef struct {
    char seed[81];
    uint8_t security;
    iota_wallet_tx_output_t * output_txs;
    uint32_t output_txs_length;
    iota_wallet_tx_input_t * input_txs;
    uint32_t input_txs_length;
    uint32_t timestamp;
} iota_wallet_bundle_description_t;

typedef int (*iota_wallet_tx_receiver_ptr_t)(iota_wallet_tx_object_t * tx_object);

typedef int (*iota_wallet_bundle_hash_receiver_ptr_t)(char * hash);

void iota_wallet_init(void);
void iota_wallet_get_address(char * seed, uint32_t idx, unsigned int security, char *address);

iota_wallet_status_codes_t iota_wallet_create_tx_bundle(iota_wallet_bundle_hash_receiver_ptr_t bundle_hash_receiver_ptr,
                                  iota_wallet_tx_receiver_ptr_t tx_receiver_ptr,
                                  iota_wallet_bundle_description_t * bundle_desciption);

void iota_wallet_construct_raw_transaction_chars(char * buffer, char * bundle_hash, iota_wallet_tx_object_t * tx);

#endif //TRANSFERS_H
