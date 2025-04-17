#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "include/aes.h"
#include "include/aes_device.h"

#define KEY_SIZE 16
#define NONCE_SIZE 16
#define BLOCK_SIZE 16

#define ERRNO_EXIT(err) do { printf("ERROR: %s\n", strerror(errno)); exit(err); } while (0);

typedef enum {
    SUCCESS = 0,
} error_g;

__device__ error_g get_counter(uint8_t counter[BLOCK_SIZE], const uint8_t nonce[NONCE_SIZE], const uint32_t round) {
    for (int i = 0; i < BLOCK_SIZE; ++i) {
        counter[i] = nonce[i];
    }

    int32_t b = BLOCK_SIZE - 1;
    uint8_t carry = round;

    uint32_t prev_counter;
    while (b >= 0) {
        prev_counter = counter[b];
        counter[b] += carry;
        if (counter[b] >= prev_counter) break;
        carry = 1;
        --b;
    }

    return SUCCESS;
}

__global__ void aes_ctr_kernel(
    uint8_t* output,
    const uint8_t* input,
    const uint8_t* round_key,
    const uint8_t* nonce,
    int input_blocks
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    printf("-------------%d-------------\n", idx);
    if (idx >= input_blocks) return;

    uint8_t counter[BLOCK_SIZE];
    get_counter(counter, nonce, idx);

    Cipher_device((state_t*)counter, round_key);

    for (int i = 0; i < BLOCK_SIZE; ++i) {
        output[idx * BLOCK_SIZE + i] = input[idx * BLOCK_SIZE + i] ^ counter[i];
    }
}

void encrypt_aes_ctr_gpu(
    const uint8_t* input,
    const uint8_t* key,
    const uint8_t* nonce,
    uint8_t* output,
    size_t size
) {
    int input_blocks = (size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    uint8_t round_key[AES_keyExpSize];
    KeyExpansion(round_key, key);

    uint8_t *d_input, *d_output, *d_key, *d_nonce;

    cudaMalloc(&d_input, size);
    cudaMalloc(&d_output, size);
    cudaMalloc(&d_key, AES_keyExpSize);
    cudaMalloc(&d_nonce, NONCE_SIZE);

    cudaMemcpy(d_input, input, size, cudaMemcpyHostToDevice);
    cudaMemcpy(d_key, round_key, AES_keyExpSize, cudaMemcpyHostToDevice);
    cudaMemcpy(d_nonce, nonce, NONCE_SIZE, cudaMemcpyHostToDevice);

     // CUDA event timing
     cudaEvent_t start, stop;
     cudaEventCreate(&start);
     cudaEventCreate(&stop);
     cudaEventRecord(start);

    int threads = 256;
    int blocks = (input_blocks + threads - 1) / threads;
    aes_ctr_kernel<<<blocks, threads>>>(d_output, d_input, d_key, d_nonce, input_blocks);
    cudaEventRecord(stop);
    cudaEventSynchronize(stop);

    float ms = 0;
    cudaEventElapsedTime(&ms, start, stop);
    printf("GPU encryption time: %.3f ms\n", ms);

    cudaMemcpy(output, d_output, size, cudaMemcpyDeviceToHost);

    cudaFree(d_input);
    cudaFree(d_output);
    cudaFree(d_key);
    cudaFree(d_nonce);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
      printf("Usage: %s <input_file>\n", argv[0]);
      return 1;
    }

    const char* filename = argv[1];

    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        perror("Failed to open input file");
        return 1;
    }

    // Get file size
    fseek(fp, 0, SEEK_END);
    size_t filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Pad file size to multiple of BLOCK_SIZE
    size_t padded_size = ((filesize + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;
    uint8_t* input = (uint8_t*)calloc(padded_size, 1);
    fread(input, 1, filesize, fp);
    fclose(fp);

    // Prepare output buffer
    uint8_t* output = (uint8_t*)malloc(padded_size);

    const uint8_t key[KEY_SIZE] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    const uint8_t nonce[NONCE_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    encrypt_aes_ctr_gpu(input, key, nonce, output, padded_size);

    char out_filename[256];
    snprintf(out_filename, sizeof(out_filename), "%s.%s", "out", "txt");

    FILE* out_fp = fopen(out_filename, "wb");
    fwrite(output, 1, padded_size, out_fp);
    fclose(out_fp);

    printf("Output written to %s\n", out_filename);

    free(input);
    free(output);

    return SUCCESS;
}
