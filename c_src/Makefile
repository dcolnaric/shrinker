CC      = gcc
EXTRA_CFLAGS =
CFLAGS_COMMON  = -Wall -Wextra -Iinclude
CFLAGS_DEBUG   = $(CFLAGS_COMMON) -g -O0 -fsanitize=address
CFLAGS_VALGRIND = $(CFLAGS_COMMON) -g -O0   # no ASan — valgrind and ASan conflict
CFLAGS_RELEASE = $(CFLAGS_COMMON) -O3 -DNDEBUG $(EXTRA_CFLAGS)
LIBS    = -lzstd -lssl -lcrypto -lm -lpthread -ldl
TARGET  = shrinker
SRCS    = src/main.c src/compress.c src/search.c \
          src/verify.c src/decompress.c src/export.c src/append.c

# Default target is debug (ASan enabled)
debug: $(SRCS) include/shrinker.h
	$(CC) $(CFLAGS_DEBUG) $(SRCS) -o $(TARGET) $(LIBS)

# valgrind build: debug symbols + no optimisation, ASan disabled
valgrind: $(SRCS) include/shrinker.h
	$(CC) $(CFLAGS_VALGRIND) $(SRCS) -o $(TARGET) $(LIBS)

# Release build.  Override CC and EXTRA_CFLAGS from the command line to
# cross-compile or build a fully static binary, e.g.:
#   make release EXTRA_CFLAGS="-static"
#   make release CC=aarch64-linux-gnu-gcc EXTRA_CFLAGS="-static"
release: $(SRCS) include/shrinker.h
	$(CC) $(CFLAGS_RELEASE) $(SRCS) -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: debug valgrind release clean
