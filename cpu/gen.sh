DIR=./inputs
mkdir -p $DIR

SIZES=(
    1
    10
    25
    50
    100
    250
    500
    1000
    2000
)

for SIZE in "${SIZES[@]}"; do
    dd if=/dev/urandom of=$DIR/$SIZE\mb.bin bs=1M count=$SIZE status=progress
done
