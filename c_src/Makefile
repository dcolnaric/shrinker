CC      = gcc
CFLAGS_COMMON  = -Wall -Wextra -I.
CFLAGS_DEBUG   = $(CFLAGS_COMMON) -g -O0 -fsanitize=address
CFLAGS_RELEASE = $(CFLAGS_COMMON) -O3 -DNDEBUG
LIBS    = -lzstd -lssl -lcrypto -lm
TARGET  = shrinker
SRCS    = main.c compress.c

# Default target is debug
debug: $(SRCS) shrinker.h
	$(CC) $(CFLAGS_DEBUG) $(SRCS) -o $(TARGET) $(LIBS)

release: $(SRCS) shrinker.h
	$(CC) $(CFLAGS_RELEASE) $(SRCS) -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: debug release clean
