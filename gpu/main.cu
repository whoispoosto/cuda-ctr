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
    if (idx >= input_blocks) return;

    uint8_t counter[BLOCK_SIZE];
    get_counter(counter, nonce, idx);

    Cipher_device((state_t*)counter, round_key);

    for (int i = 0; i < BLOCK_SIZE; ++i) {
        output[idx * BLOCK_SIZE + i] = input[idx * BLOCK_SIZE + i] ^ counter[i];
    }
}

__global__ void aes_ctr_kernel_coarsening(
    uint8_t* output,
    const uint8_t* input,
    const uint8_t* round_key,
    const uint8_t* nonce,
    int input_blocks,
    int blocks_per_thread
) {
    int global_thread_idx = blockIdx.x * blockDim.x + threadIdx.x;
    int start_block = global_thread_idx * blocks_per_thread;

    uint8_t counter[BLOCK_SIZE];

    for (int i = 0; i < blocks_per_thread; ++i) {
        int block_idx = start_block + i;
        if (block_idx >= input_blocks) return;

        get_counter(counter, nonce, block_idx);
        Cipher_device((state_t*)counter, round_key);

        for (int j = 0; j < BLOCK_SIZE; ++j) {
            output[block_idx * BLOCK_SIZE + j] = 
                input[block_idx * BLOCK_SIZE + j] ^ counter[j];
        }
    }
}

__global__ void aes_ctr_kernel_coalesced(
    uint8_t* output,
    const uint8_t* input,
    const uint8_t* round_key,
    const uint8_t* nonce,
    int input_blocks,
    int blocks_per_thread
) {
    int global_thread_idx = blockIdx.x * blockDim.x + threadIdx.x;
    int start_block = global_thread_idx * blocks_per_thread;

    alignas(16) uint8_t counter[BLOCK_SIZE]; // ensures 16-byte alignment

    for (int i = 0; i < blocks_per_thread; ++i) {
        int block_idx = start_block + i;
        if (block_idx >= input_blocks) return;

        // Generate and encrypt the counter block
        get_counter(counter, nonce, block_idx);
        Cipher_device((state_t*)counter, round_key);

        // Cast input/output/counter to 128-bit wide types
        const uint4* input_block = reinterpret_cast<const uint4*>(&input[block_idx * BLOCK_SIZE]);
        uint4* output_block = reinterpret_cast<uint4*>(&output[block_idx * BLOCK_SIZE]);
        const uint4* counter_block = reinterpret_cast<const uint4*>(counter);

        // XOR the entire 16-byte block in 4 × 32-bit words
        output_block[0].x = input_block[0].x ^ counter_block[0].x;
        output_block[0].y = input_block[0].y ^ counter_block[0].y;
        output_block[0].z = input_block[0].z ^ counter_block[0].z;
        output_block[0].w = input_block[0].w ^ counter_block[0].w;
    }
}

__global__ void aes_ctr_kernel_coarsening_shared(
    uint8_t* output,
    const uint8_t* input,
    const uint8_t* round_key,
    const uint8_t* nonce,
    int input_blocks,
    int blocks_per_thread
) {
    extern __shared__ uint8_t shared_round_key[];

    // One thread per block copies round key into shared memory
    int tid = threadIdx.x;
    int threads_in_block = blockDim.x;
    int total_key_size = AES_keyExpSize;

    for (int i = tid; i < total_key_size; i += threads_in_block) {
        shared_round_key[i] = round_key[i];
    }
    __syncthreads();  // Ensure all round key is loaded

    int global_thread_idx = blockIdx.x * blockDim.x + threadIdx.x;
    int start_block = global_thread_idx * blocks_per_thread;

    uint8_t counter[BLOCK_SIZE];

    for (int i = 0; i < blocks_per_thread; ++i) {
        int block_idx = start_block + i;
        if (block_idx >= input_blocks) return;

        get_counter(counter, nonce, block_idx);
        Cipher_device((state_t*)counter, shared_round_key);  // Use shared key

        for (int j = 0; j < BLOCK_SIZE; ++j) {
            output[block_idx * BLOCK_SIZE + j] = 
                input[block_idx * BLOCK_SIZE + j] ^ counter[j];
        }
    }
}

__global__ void aes_ctr_kernel_coarsening_shared_coal(
    uint8_t* output,
    const uint8_t* input,
    const uint8_t* round_key,
    const uint8_t* nonce,
    int input_blocks,
    int blocks_per_thread
) {
    extern __shared__ uint8_t shared_round_key[];

    // One thread per block copies round key into shared memory
    int tid = threadIdx.x;
    int threads_in_block = blockDim.x;
    int total_key_size = AES_keyExpSize;

    for (int i = tid; i < total_key_size; i += threads_in_block) {
        shared_round_key[i] = round_key[i];
    }
    __syncthreads();  // Ensure all round key is loaded

    int global_thread_idx = blockIdx.x * blockDim.x + threadIdx.x;
    int start_block = global_thread_idx * blocks_per_thread;

    alignas(16) uint8_t counter[BLOCK_SIZE];

    for (int i = 0; i < blocks_per_thread; ++i) {
        int block_idx = start_block + i;
        if (block_idx >= input_blocks) return;

        get_counter(counter, nonce, block_idx);
        Cipher_device((state_t*)counter, shared_round_key);  // Use shared key

        // Cast input/output/counter to 128-bit wide types
        const uint4* input_block = reinterpret_cast<const uint4*>(&input[block_idx * BLOCK_SIZE]);
        uint4* output_block = reinterpret_cast<uint4*>(&output[block_idx * BLOCK_SIZE]);
        const uint4* counter_block = reinterpret_cast<const uint4*>(counter);

        // XOR the entire 16-byte block in 4 × 32-bit words
        output_block[0].x = input_block[0].x ^ counter_block[0].x;
        output_block[0].y = input_block[0].y ^ counter_block[0].y;
        output_block[0].z = input_block[0].z ^ counter_block[0].z;
        output_block[0].w = input_block[0].w ^ counter_block[0].w;
    }
}

void encrypt_aes_ctr_gpu(
    const uint8_t* input,
    const uint8_t* key,
    const uint8_t* nonce,
    uint8_t* output,
    size_t size,
    int threads, 
    int coarsening
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

    int blocks = (input_blocks + threads - 1) / threads;
    int shared_mem_bytes = AES_keyExpSize * sizeof(uint8_t);
    // aes_ctr_kernel_coarsening_shared<<<blocks, threads, shared_mem_bytes>>>(
        // d_output, d_input, d_key, d_nonce, input_blocks, coarsening);
    // aes_ctr_kernel_coarsening<<<blocks, threads>>>(d_output, d_input, d_key, d_nonce, input_blocks, coarsening);
    // aes_ctr_kernel_coalesced<<<blocks, threads>>>(d_output, d_input, d_key, d_nonce, input_blocks, coarsening);
    // aes_ctr_kernel<<<blocks, threads>>>(d_output, d_input, d_key, d_nonce, input_blocks);
    aes_ctr_kernel_coarsening_shared_coal<<<blocks, threads, shared_mem_bytes>>>(
        d_output, d_input, d_key, d_nonce, input_blocks, coarsening);

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

void print_gpu_info() {
    cudaDeviceProp prop;
    int device;

    cudaGetDevice(&device);
    cudaGetDeviceProperties(&prop, device);

    printf("========== GPU Device Info ==========\n");
    printf("Device: %s\n", prop.name);
    printf("Total global memory: %.2f MB\n", prop.totalGlobalMem / (1024.0 * 1024.0));
    printf("Shared memory per block: %lu bytes\n", prop.sharedMemPerBlock);
    printf("Registers per block: %d\n", prop.regsPerBlock);
    printf("Warp size: %d\n", prop.warpSize);
    printf("Max threads per block: %d\n", prop.maxThreadsPerBlock);
    printf("Max thread dimensions: [%d, %d, %d]\n", 
           prop.maxThreadsDim[0], prop.maxThreadsDim[1], prop.maxThreadsDim[2]);
    printf("Max grid size: [%d, %d, %d]\n", 
           prop.maxGridSize[0], prop.maxGridSize[1], prop.maxGridSize[2]);
    printf("Multiprocessor count: %d\n", prop.multiProcessorCount);
    printf("Max threads per multiprocessor: %d\n", prop.maxThreadsPerMultiProcessor);
    printf("Clock rate: %.2f MHz\n", prop.clockRate / 1000.0);
    printf("Memory clock rate: %.2f MHz\n", prop.memoryClockRate / 1000.0);
    printf("Memory bus width: %d bits\n", prop.memoryBusWidth);
    printf("L2 cache size: %d bytes\n", prop.l2CacheSize);
    printf("=====================================\n");
}

int main(int argc, char* argv[]) {
    // print_gpu_info();

    int threads = 1024;
    int coarsening = 2;

    if (argc < 2 || argc > 4) {
        fprintf(stderr, "Usage: %s <input_file> [threads] [coarsening]\n", argv[0]);
        return 1;
    }

    if (argc == 3) {
        threads = atoi(argv[2]);
        printf("Using %d threads per block\n", threads);
    }

    if (argc == 4) {
        coarsening = atoi(argv[3]);
        printf("Using coarsening factor of %d\n", coarsening);
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

    encrypt_aes_ctr_gpu(input, key, nonce, output, padded_size, threads, coarsening);

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
