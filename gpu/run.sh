#!/bin/bash

# Compile the program
echo "Compiling CUDA program..."
nvcc main.cu aes.cu aes_device.cu -o main -rdc=true -diag-suppress 177

if [ $? -ne 0 ]; then
    echo "Compilation failed!"
    exit 1
fi

# Create output directory for results
mkdir -p benchmark_results
RESULTS_FILE="benchmark_results/timing_results.csv"

# Write CSV header
echo "File_Size_MB,File_Size_Bytes,Thread_Count,Coarsening_Factor,Encryption_Time_ms,Throughput_MBps" > $RESULTS_FILE

# Define test parameters
FILE_SIZES=(1 20 25 50 100 250 500 1000 2000)
THREAD_COUNTS=(1024)
COARSENING_FACTORS=(2)

# Generate test files and run benchmarks
for threads in "${THREAD_COUNTS[@]}"; do
    for coarsening in "${COARSENING_FACTORS[@]}"; do
        for size in "${FILE_SIZES[@]}"; do
            echo "========================================"
            echo "Testing with file size: $size MB, threads: $threads, coarsening: $coarsening"
            
            TEST_FILE="test_${size}MB.dat"
            echo "Generating $TEST_FILE..."
            dd if=/dev/urandom of=$TEST_FILE bs=1M count=$size status=none
            
            file_size_bytes=$(stat -c%s "$TEST_FILE")

            echo "Running encryption on $TEST_FILE..."
            output=$(./main $TEST_FILE $threads $coarsening)

            encryption_time=$(echo "$output" | grep "GPU encryption time" | awk '{print $4}')
            throughput=$(echo "scale=2; $size / ($encryption_time / 1000)" | bc)

            echo "Encryption time: $encryption_time ms"
            echo "Throughput: $throughput MB/s"

            echo "$size,$file_size_bytes,$threads,$coarsening,$encryption_time,$throughput" >> $RESULTS_FILE

            rm -f "$TEST_FILE" "out.txt"
        done
    done
done

# Generate summary
echo "========================================"
echo "Benchmark completed!"
echo "Results saved to $RESULTS_FILE"
echo "========================================"
echo "Summary Report:"
echo "========================================"
printf "%-10s %-10s %-10s %-15s %-12s\n" "Size(MB)" "Threads" "Coarsen" "Time(ms)" "Throughput"
echo "--------------------------------------------------------------"
tail -n +2 "$RESULTS_FILE" | sort -t, -k1,1n -k3,3n -k4,4n | while IFS=, read -r size bytes threads coarsening time throughput; do
    printf "%-10s %-10s %-10s %-15s %-12s\n" "$size" "$threads" "$coarsening" "$time" "$throughput"
done
