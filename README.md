# embedded IOTA C library

#### Alpha version: 
API might change over time. Don't use it in production environments!

## Design:

This library is designed to make it possible to use IOTA on really small embedded devices.
The library has the following attributes:

- POSIX compatible Threads (pthread)
- Thread-safe
- Low footprint
- Usable on devices without MMU
- C99 compliant 


## A notice to trytes:

Due to confusion of several people, a short explanation about the conversions.
The API for the conversion is available in conversion.c and conversion.h.

In this context the following words have the following meaning:

**Chars:** Means the char representation of an Tryte. (ASCII character) A - Z and 9.  (base-27 encoded ternary number)
**Bytes:** Means a byte representation of trytes, optimized for low storage and memory usage.  
**Trits:** Means a int8_t array representation of trits.   
**Trytes:** Means a int8_t array representation of trytes.

### Conversion space ratio

One transaction = 2673 trytes = ((2673/81) * 48) Bytes = 2673*3 Trits = 2673 chars

## Usage:
### Generation of addresses
Coming soon.

### Generation of transactions and bundles
Coming soon.



