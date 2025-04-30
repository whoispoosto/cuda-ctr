# Bash script for benchmarking CPU

INDIR=./inputs
OUTDIR=./outputs
MODE="sequential"

MB=1024*1024

# For MacOS only
alias date="gdate"

# Create output directory
rm -rf $OUTDIR
mkdir $OUTDIR

echo "Running $MODE program on input files..."

for file in "$INDIR"/*; do
    filename=$(basename $file)
    echo "Running input file: $filename"

    start=$(($(date +%s%N)/1000000))
    ./$MODE $INDIR/$filename $OUTDIR/$filename > /dev/null
    end=$(($(date +%s%N)/1000000))

    elapsed=$(expr $end - $start)
    echo "Elapsed time: $elapsed ms"

    # Store the elapsed time in a dynamically-named variable
    # Ex: time_1000mb=(elapsed time)
    # The file extension is removed
    declare "time_${filename%.*}=$elapsed"
done

echo "Done!\n\n"

echo "--------------------------------------"
echo "Summary Report (CPU $MODE)"
echo "======================================"
echo "Size (MB)\tTime (ms)\tThroughout (MB/s)"
echo "--------------------------------------"

# From ChatGPT: iterates over directory in ascending file-size order
for file in $(find $OUTDIR -type f -exec du -k {} + | sort -n | cut -f2-); do
    filename=$(basename $file)

    size_b=$(wc -c < "$file")
    size_mb=$((size_b / MB))

    # Grab the time stored in the dynamically-named variable
    timekey="time_${filename%.*}"
    time="${!timekey}"

    throughput=$(expr $size_b / $time)
    throughput=$((throughput * 1000 / MB))

    echo "$size_mb\t\t$time\t\t$throughput"
done
