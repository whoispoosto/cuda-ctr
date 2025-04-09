# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -DCBC=0 -DECB=0 -DCTR=1

# Directories
INCLUDE_DIR = include
SRC_DIR = .
OBJ_DIR = obj

# Source files (all .c files in the root directory)
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

# Target executable
TARGET = main

# Default rule
all: create_dirs $(TARGET)

# Rule to create object directory
create_dirs:
	@mkdir -p $(OBJ_DIR)

# Linking rule
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

# Compilation rule
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean rule
clean:
	rm -rf $(OBJ_DIR) $(TARGET)

# Phony targets
.PHONY: all clean create_dirs
