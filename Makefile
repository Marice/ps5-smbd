PS5_HOST ?= 192.168.68.112
PS5_PORT ?= 9021
TITLE    := ps5-smbd
ELF      := $(TITLE).elf
VERSION  := 0.2.0

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
endif

SRCS := src/main.c src/fs.c src/rpc.c src/names.c src/wsd.c src/shares.c
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
	$(CC) $(CFLAGS) -I.deps/ps5/include -o $@ $(SRCS) .deps/ps5/lib/libdcerpc.a .deps/ps5/lib/libsmb2.a -lkernel_sys -lSceSystemService -lpthread

# The same server on this computer, on port 4450, sharing two folders under build/ (for tests).
host: .deps/host/lib/libsmb2.a $(SRCS) $(HDRS)
	mkdir -p build/data build/mnt
	cc $(CFLAGS) -DSMBD_HOST -DSMBD_PORT=4450 -DSMBD_DATA='"$(CURDIR)/build/data"' -DSMBD_MNT='"$(CURDIR)/build/mnt"' -DSMBD_TRACE_FILE='"$(CURDIR)/build/smbd.log"' \
	  -I.deps/host/include -o ps5-smbd-host $(SRCS) \
	  -DSMBD_NBNS_PORT=1370 -DSMBD_MDNS_PORT=53530 -DSMBD_LLMNR_PORT=53550 -DSMBD_WSD_PORT=37020 -DSMBD_WSD_HTTP_PORT=53570 \
	  .deps/host/lib/libdcerpc.a .deps/host/lib/libsmb2.a -lpthread

deploy: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $(ELF)

clean:
	rm -f $(ELF) ps5-smbd-host

.PHONY: all require-sdk host deploy clean
