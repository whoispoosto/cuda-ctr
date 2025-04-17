#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include "aes.h"

// AES-128-ctr
// https://cryptii.com/pipes/aes-encryption
// INPUT: 6b c1 be e2 2e 40 9f 96 e9 3d 7e 11 73 93 17 2a
// KEY: 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
// NONCE: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f

// https://github.com/kokke/tiny-AES-c/blob/23856752fbd139da0b8ca6e471a13d5bcc99a08d/aes.c#L538

#define KEY_SIZE 16             // 128-bit
#define NONCE_SIZE 16           // 128-bit, aka initialization vector (IV) -- some implementations do 64-bit
#define BLOCK_SIZE 16           // 128-bit, regardless of key size
#define INPUT_SIZE_BLOCKS 2     // input size in blocks

#define ERRNO_EXIT(err) do { printf("ERROR: %s\n", strerror(errno)); exit(err); } while (0);
#define RET(err, str, ...) do { printf("ERROR: " str "\n",  ##__VA_ARGS__); exit(err); } while (0);

typedef enum {
    SUCCESS = 0,
    ERR_GENERIC = -1,
    ERR_FORK = -2,
    ERR_MMAP = -3
} error_t;

error_t get_counter(uint8_t counter[BLOCK_SIZE], const uint8_t nonce[NONCE_SIZE], const uint32_t round) {
    // Copy the original nonce into the counter
    // In our implementation, BLOCK_SIZE == NONCE_SIZE so this is safe
    // but this could break if NONCE_SIZE is changed
    memcpy(counter, nonce, BLOCK_SIZE);

    // Handle incrementing for the round
    int32_t b = BLOCK_SIZE - 1;
    uint8_t carry = round;
    
    uint32_t prev_counter;

    while (b >= 0) {
        prev_counter = counter[b]; 
        counter[b] += carry;

        // Check if overflow does NOT occur
        // Overflow occurs if the new value is less than the previous value
        // If it doesn't, we can break as normal
        if (counter[b] >= prev_counter) {
            break; 
        }

        // If overflow does occur, we need to handle wrap-around
        // Simply set carry to 1
        // The current position will naturally wrap-around properly
        carry = 1;
        --b;
    }

    return SUCCESS;
}

error_t aes(uint8_t output[BLOCK_SIZE], const uint8_t counter[BLOCK_SIZE], const uint8_t key[KEY_SIZE]) {
    uint8_t buf[BLOCK_SIZE];
    memcpy(buf, counter, BLOCK_SIZE);

    Cipher((state_t *)buf, key);

    memcpy(output, buf, BLOCK_SIZE);

    return SUCCESS;
}

int main() {
    const uint8_t key[KEY_SIZE] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };

    uint8_t round_key[AES_keyExpSize];
    KeyExpansion(round_key, key);

    const uint8_t nonce[NONCE_SIZE] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };

    const uint8_t input[INPUT_SIZE_BLOCKS * BLOCK_SIZE] = {
        0x6b, 0xc1, 0xbe, 0xe2,
        0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11,
        0x73, 0x93, 0x17, 0x2a,
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };

    // Create a block of memory
#ifdef PARALLEL
    printf("parallel on!\n");

    uint8_t *output = (uint8_t *)mmap(NULL, sizeof(INPUT_SIZE_BLOCKS * BLOCK_SIZE), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    if (output == MAP_FAILED) {
        RET(ERR_MMAP, "mmap failed");
    }

    pid_t pid;
#else
    uint8_t output[INPUT_SIZE_BLOCKS * BLOCK_SIZE];
#endif

    uint8_t counter[BLOCK_SIZE];
    uint8_t counter_encrypted[BLOCK_SIZE];

    uint8_t *block_out;
    const uint8_t *block_in;

    error_t err;

    // Iterate over every block in the input
    for (uint32_t i = 0; i < INPUT_SIZE_BLOCKS; ++i) {
#ifdef PARALLEL
        pid = fork();

        // Check if fork() succeeded
        if (pid == -1) {
            RET(ERR_FORK, "fork failed");
        }

        // If parent task, don't do the actual work of the loop
        if (pid != 0) {
            continue;
        }
#endif

        // Get the current counter
        if ((err = get_counter(counter, nonce, i)) != SUCCESS) {
            RET(err, "get_counter failed");
        };

        // Get a pointer to the current input and output blocks
        block_out = &output[i * BLOCK_SIZE];
        block_in = &input[i * BLOCK_SIZE];

        // Run AES algorithm on the current counter
        if ((err = aes(counter_encrypted, counter, round_key)) != SUCCESS) {
            RET(err, "aes_ctr failed");
        }

        // XOR the AES-encrypted counter with the plaintext input
        for (uint32_t b = 0; b < BLOCK_SIZE; ++b) {
            block_out[b] = block_in[b] ^ counter_encrypted[b];
        }

#ifdef PARALLEL
        // Exit the child after execution is complete
        _exit(0);
#endif
    }

#ifdef PARALLEL
    for (uint32_t i = 0; i < INPUT_SIZE_BLOCKS; ++i) {
        wait(NULL);
    }
#endif

    // DEBUG: Print out the encrypted block
    for (uint32_t i = 0; i < INPUT_SIZE_BLOCKS; ++i) {
        uint8_t *block_out = &output[i * BLOCK_SIZE];

        for (uint32_t b = 0; b < BLOCK_SIZE; ++b) {
            printf("0x%x ", block_out[b]);
        }

        printf("\n");
    }

#ifdef PARALLEL
    if (munmap(output, INPUT_SIZE_BLOCKS * BLOCK_SIZE) == -1) {
        RET(ERR_MMAP, "munmap failed");
    }
#endif

    return SUCCESS;
}
