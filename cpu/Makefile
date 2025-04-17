# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -DCBC=0 -DECB=0 -DCTR=1
PARALLEL_FLAG = -DPARALLEL

# Directories
INCLUDE_DIR = include
SRC_DIR = src
OBJ_DIR = obj

# Source files (all .c files in the root directory)
SRCS = $(wildcard $(SRC_DIR)/*.c)
SEQUENTIAL_OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%_sequential.o,$(SRCS))
PARALLEL_OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%_parallel.o,$(SRCS))

# Target executables
TARGET_SEQUENTIAL = sequential
TARGET_PARALLEL = parallel

# Default rule
all: create_dirs $(TARGET_SEQUENTIAL) $(TARGET_PARALLEL)

# Rule to create object directory
create_dirs:
	@mkdir -p $(OBJ_DIR)

# Linking rules
$(TARGET_SEQUENTIAL): $(SEQUENTIAL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(TARGET_PARALLEL): $(PARALLEL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

# Compilation rules
$(OBJ_DIR)/%_sequential.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%_parallel.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(PARALLEL_FLAG) -c $< -o $@

# Clean rule
clean:
	rm -rf $(OBJ_DIR) $(TARGET_SEQUENTIAL)
	rm -rf $(OBJ_DIR) $(TARGET_PARALLEL)

# Phony targets
.PHONY: all clean create_dirs
