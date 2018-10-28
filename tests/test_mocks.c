#include "test_common.h"
#include <stdio.h>
#include "iota/bundle.h"
#include "keccak/sha3.h"

void throw_exception(const char *expression, const char *file, int line)
{
    mock_assert(false, expression, file, line);
}

bool flash_is_init()
{
    return true;
}

__attribute__((weak)) void derive_seed_bip32(const unsigned int *path,
                                             unsigned int pathLength,
                                             unsigned char *seed_bytes)
{
    UNUSED(path);
    UNUSED(pathLength);
    UNUSED(seed_bytes);

    char msg[100];
    snprintf(msg, 100, "%s should not be called", __FUNCTION__);
    mock_assert(false, msg, __FILE__, __LINE__);
}

__attribute__((weak)) void io_send(const void *ptr, unsigned int length,
                                   unsigned short sw)

{
    UNUSED(ptr);
    UNUSED(length);
    UNUSED(sw);

    char msg[100];
    snprintf(msg, 100, "%s should not be called", __FUNCTION__);
    mock_assert(false, msg, __FILE__, __LINE__);
}
