PS5_HOST ?= 192.168.68.112
PS5_PORT ?= 9021
TITLE    := ps5-smbd
ELF      := $(TITLE).elf
VERSION  := 0.1.0

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
endif

LIBSMB2_SRC := .deps/build-ps5/libsmb2-727feaaa6d0f4fed1bae57745fbc2c5db9a30e64/include
SRCS := src/main.c src/fs.c
HDRS := $(wildcard src/*.h)

CFLAGS := -Wall -Wextra -O2 -std=gnu11 -DSMBD_VERSION='"$(VERSION)"' -Isrc

all: $(ELF)

require-sdk:
	@test -n "$(PS5_PAYLOAD_SDK)" || { echo "PS5_PAYLOAD_SDK is undefined; export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk"; exit 1; }

.deps/ps5/lib/libsmb2.a:
	tools/build-libsmb2.sh ps5

.deps/host/lib/libsmb2.a:
	tools/build-libsmb2.sh host

$(ELF): require-sdk .deps/ps5/lib/libsmb2.a $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) -I.deps/ps5/include -I$(LIBSMB2_SRC) -o $@ $(SRCS) .deps/ps5/lib/libsmb2.a -lkernel_sys -lpthread

# The same server on this computer, on port 4450, sharing two folders under build/ (for tests).
host: .deps/host/lib/libsmb2.a $(SRCS) $(HDRS)
	mkdir -p build/data build/mnt
	cc $(CFLAGS) -DSMBD_HOST -DSMBD_PORT=4450 -DSMBD_DATA='"$(CURDIR)/build/data"' -DSMBD_MNT='"$(CURDIR)/build/mnt"' -DSMBD_TRACE_FILE='"$(CURDIR)/build/smbd.log"' \
	  -I.deps/host/include -I.deps/build-host/libsmb2-727feaaa6d0f4fed1bae57745fbc2c5db9a30e64/include -o ps5-smbd-host $(SRCS) \
	  .deps/host/lib/libsmb2.a

deploy: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $(ELF)

clean:
	rm -f $(ELF) ps5-smbd-host

.PHONY: all require-sdk host deploy clean
