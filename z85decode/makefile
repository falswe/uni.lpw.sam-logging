CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = 

# Paths to Z85 library
Z85_DIR = ../z85/src
INCLUDES = -I$(Z85_DIR)

# Source files
SRCS = z85decode.c $(Z85_DIR)/z85.c
OBJS = $(SRCS:.c=.o)
TARGET = z85decode

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean