#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

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

#define ERRNO_EXIT(err) do { printf("ERROR: %s\n", strerror(errno)); exit(err); } while (0);
#define RET(err, str, ...) do { printf("ERROR: " str "\n",  ##__VA_ARGS__); exit(err); } while (0);

#define NUM_ARGS 3
#define ARG_PROGNAME 0
#define ARG_INFILENAME 1
#define ARG_OUTFILENAME 2

#define MB (1024 * 1024)
#define BUFFER_SIZE ((MB * 2047) - 1 + MB) // Max input size (stored on heap). This weird expression prevents overflow

#define COARSENING_FACTOR (BLOCK_SIZE * 256) // Must be a multiple of block size

typedef enum {
    SUCCESS = 0,
    ERR_GENERIC = -1,
    ERR_FORK = -2,
    ERR_MMAP = -3,
    ERR_USAGE = -4,
    ERR_FILE = -5
} error_t;

error_t get_counter(uint8_t counter[BLOCK_SIZE], const uint8_t nonce[NONCE_SIZE], const uint32_t round) {
    // Copy the original nonce into the counter
    // In our implementation, BLOCK_SIZE == NONCE_SIZE so this is safe
    // but this could break if NONCE_SIZE is changed
    memcpy(counter, nonce, BLOCK_SIZE);

    // Handle incrementing for the round
    int32_t b = BLOCK_SIZE - 1;

    // TODO: output works, but counters are repeating (security risk)
    // change this to 32-bit
    uint8_t carry = round;
    uint8_t prev_counter;

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
        // The current position will naturally wrap-around properly with the arithmetic
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

int main(int argc, char **argv) {
    if (argc < NUM_ARGS) {
        RET(ERR_USAGE, "Program usage: %s [input filename] [output filename]", argv[ARG_PROGNAME]);
    }

    // Open the input file for reading
    FILE *inputstream = fopen(argv[ARG_INFILENAME], "r");

    if (inputstream == NULL) {
        RET(ERR_FILE, "Unable to open input file");
    }

    // Create a buffer to read file contents into
    uint8_t *input = malloc(BUFFER_SIZE);
    memset(input, 0, BUFFER_SIZE);

    // Read the contents of the file into a buffer
    size_t filesize = fread(input, 1, BUFFER_SIZE, inputstream);
    printf("Input file size: %lu MB\n", filesize / MB);

    if (ferror(inputstream)) {
        RET(ERR_FILE, "Unable to read input file");
    }

    fclose(inputstream);

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

    // Calculated the input size in blocks, rounded up
    const uint32_t input_size_blocks = (filesize + (BLOCK_SIZE - 1)) / BLOCK_SIZE;
    const uint32_t output_size = input_size_blocks * BLOCK_SIZE;

    // Create a block of memory
#ifdef PARALLEL
    printf("parallel on!\n");

    uint8_t *output = (uint8_t *)mmap(NULL, output_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    if (output == MAP_FAILED) {
        RET(ERR_MMAP, "mmap failed");
    }

    pid_t pid;
#else
    uint8_t *output = malloc(output_size);
    memset(output, 0, output_size);
#endif

    uint8_t counter[BLOCK_SIZE];
    uint8_t counter_encrypted[BLOCK_SIZE];

    uint8_t *block_out;
    const uint8_t *block_in;

    error_t err;

    printf("Starting timer...\n");
    clock_t start = clock();

    // Iterate over every block in the input
    for (uint32_t i = 0; i < input_size_blocks; i += COARSENING_FACTOR) {
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

        for (uint32_t block = i; block < i + COARSENING_FACTOR && block < input_size_blocks; ++block) {
            // Get the current counter
            if ((err = get_counter(counter, nonce, block)) != SUCCESS) {
                RET(err, "get_counter failed");
            }

            // Get a pointer to the current input and output blocks
            block_out = &output[block * BLOCK_SIZE];
            block_in = &input[block * BLOCK_SIZE];

            // Run AES algorithm on the current counter
            if ((err = aes(counter_encrypted, counter, round_key)) != SUCCESS) {
                RET(err, "aes_ctr failed");
            }

            // XOR the AES-encrypted counter with the plaintext input
            for (uint32_t b = 0; b < BLOCK_SIZE; ++b) {
                block_out[b] = block_in[b] ^ counter_encrypted[b];
            }
        }

#ifdef PARALLEL
        // Exit the child after execution is complete
        _exit(0);
#endif
    }

#ifdef PARALLEL
    for (uint32_t i = 0; i < input_size_blocks; ++i) {
        wait(NULL);
    }
#endif

    // DEBUG: Print out the encrypted block
    /*for (uint32_t i = 0; i < input_size_blocks; ++i) {
        uint8_t *block_out = &output[i * BLOCK_SIZE];

        for (uint32_t b = 0; b < BLOCK_SIZE; ++b) {
            printf("0x%x ", block_out[b]);
        }

        printf("\n");
    }*/

    printf("Stopping timer...\n");
    clock_t stop = clock();

    printf("Timer done! Elapsed time: %.4f secs\n", (double)(stop - start) / CLOCKS_PER_SEC);

    // Open an output file for writing
    FILE *outputstream = fopen(argv[ARG_OUTFILENAME], "w");

    if (outputstream == NULL) {
        RET(ERR_FILE, "Unable to open input file");
    }

    // Write the contents of the output to the stream
    fwrite(output, 1, output_size, outputstream); 

    if (ferror(outputstream)) {
        RET(ERR_FILE, "Unable to read input file");
    }

    fclose(outputstream);

    // Free input memory
    free(input);

    // Free output memory
#ifdef PARALLEL
    if (munmap(output, output_size) == -1) {
        RET(ERR_MMAP, "munmap failed");
    }
#else
    free(output);
#endif

    return SUCCESS;
}
