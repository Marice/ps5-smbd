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

# The PS2 (EE): the memory cards as \\<ip>\mc0 and \mc1, no discovery, no srvsvc. Needs the
# ps2dev toolchain (PS2DEV, PS2SDK); make ps2-docker builds it in the ps2dev/ps2dev image.
PS2_ELF  := ps2-smbd.elf
PS2_SRCS := src/main.c src/fs.c src/shares.c src/ps2.c
PS2_IRX  := build/ps2/dev9_irx.c build/ps2/netman_irx.c build/ps2/smap_irx.c build/ps2/iomanx_irx.c \
            build/ps2/filexio_irx.c build/ps2/sio2man_irx.c build/ps2/mcman_irx.c build/ps2/mcserv_irx.c
# a fixed address instead of DHCP: make ps2 PS2_IP=192.168.1.50 PS2_GW=192.168.1.1 [PS2_NETMASK=255.255.255.0]
PS2_NETMASK ?= 255.255.255.0
PS2_NET  := $(if $(PS2_IP),-DSMBD_PS2_IP='"$(PS2_IP)"' -DSMBD_PS2_GW='"$(PS2_GW)"' -DSMBD_PS2_NETMASK='"$(PS2_NETMASK)"')

.deps/ps2/lib/libsmb2.a:
	tools/build-libsmb2.sh ps2

build/ps2/dev9_irx.c: $(PS2SDK)/iop/irx/ps2dev9.irx
	mkdir -p build/ps2 && bin2c $< $@ DEV9_irx
build/ps2/netman_irx.c: $(PS2SDK)/iop/irx/netman.irx
	mkdir -p build/ps2 && bin2c $< $@ NETMAN_irx
build/ps2/smap_irx.c: $(PS2SDK)/iop/irx/smap.irx
	mkdir -p build/ps2 && bin2c $< $@ SMAP_irx
build/ps2/iomanx_irx.c: $(PS2SDK)/iop/irx/iomanX.irx
	mkdir -p build/ps2 && bin2c $< $@ IOMANX_irx
build/ps2/filexio_irx.c: $(PS2SDK)/iop/irx/fileXio.irx
	mkdir -p build/ps2 && bin2c $< $@ FILEXIO_irx
build/ps2/sio2man_irx.c: $(PS2SDK)/iop/irx/sio2man.irx
	mkdir -p build/ps2 && bin2c $< $@ SIO2MAN_irx
build/ps2/mcman_irx.c: $(PS2SDK)/iop/irx/mcman.irx
	mkdir -p build/ps2 && bin2c $< $@ MCMAN_irx
build/ps2/mcserv_irx.c: $(PS2SDK)/iop/irx/mcserv.irx
	mkdir -p build/ps2 && bin2c $< $@ MCSERV_irx

ps2: $(PS2_ELF)

$(PS2_ELF): .deps/ps2/lib/libsmb2.a $(PS2_SRCS) $(HDRS) $(PS2_IRX)
	mips64r5900el-ps2-elf-gcc -D_EE -G0 -O2 -Wall -std=gnu11 -DSMBD_VERSION='"$(VERSION)"' -DSMBD_HOST \
	  -DSMBD_TRACE_FILE='"mc0:/smbd.log"' $(PS2_NET) $(PS2_CFLAGS) \
	  -Isrc/ps2 -Isrc -I.deps/ps2/include -I$(PS2SDK)/ee/include -I$(PS2SDK)/common/include \
	  -T$(PS2SDK)/ee/startup/linkfile -L$(PS2SDK)/ee/lib -Wl,-zmax-page-size=128 -Wl,--wrap=stat -o $@ $(PS2_SRCS) $(PS2_IRX) \
	  .deps/ps2/lib/libsmb2.a -lnetman -lps2ip -lmc -lfileXio -lpatches -ldebug

DOCKER ?= docker
ps2-docker:
	$(DOCKER) run --rm -v "$(CURDIR)":/src:z -w /src ps2dev/ps2dev:latest \
	  sh -c 'apk add -q bash cmake curl make patch && make ps2 PS2_IP=$(PS2_IP) PS2_GW=$(PS2_GW) PS2_NETMASK=$(PS2_NETMASK)'

deploy: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $(ELF)

clean:
	rm -f $(ELF) ps5-smbd-host $(PS2_ELF) $(PS2_IRX)

.PHONY: all require-sdk host ps2 ps2-docker deploy clean
