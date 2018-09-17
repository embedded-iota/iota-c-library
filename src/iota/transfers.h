#ifndef TRANSFERS_H
#define TRANSFERS_H

#include <stdint.h>

typedef struct TX_OBJECT {
    char signatureMessageFragment[2187];
    char address[81];
    int64_t value;
    char obsoleteTag[27];
    uint32_t timestamp;
    uint32_t currentIndex;
    uint32_t lastIndex;
    char bundle[81];
    char trunkTransaction[81];
    char branchTransaction[81];
    char tag[27];
    char nonce[27];
} TX_OBJECT;

typedef struct TX_OUTPUT {
        char address[81];
        int64_t value;
        char message[2187];
        char tag[27];
} TX_OUTPUT;

typedef struct TX_INPUT {
        int64_t balance;
        uint32_t key_index;
} TX_INPUT;

typedef int (*tx_receiver_t)(TX_OBJECT * tx_object);

typedef int (*bundle_hash_receiver)(char * hash);

void prepare_transfers_light(char *seed, uint8_t security, TX_OUTPUT *outputs,
                             unsigned int num_outputs, TX_INPUT *inputs, unsigned int num_inputs,
                             tx_receiver_t tx_receiver_func, bundle_hash_receiver bundle_receiver_func);

void prepare_transfers(const char *seed, uint8_t security, TX_OUTPUT *outputs,
                       int num_outputs, TX_INPUT *inputs, int num_inputs,
                       char transaction_chars[][2673]);

#endif //TRANSFERS_H
