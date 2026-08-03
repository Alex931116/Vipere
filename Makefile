CC = x86_64-w64-mingw32-g++
BOF_CFLAGS = -Wall -O2 -DUNICODE -D_UNICODE -DBOF -c \
    -fno-exceptions -fno-rtti -mno-stack-arg-probe -fno-asynchronous-unwind-tables
DIST = dist

all: $(DIST)/lpe_vs_bootstrap.x64.o

$(DIST)/lpe_vs_bootstrap.x64.o: src/lpe_vs_bootstrap_bof.cpp src/beacon.h
	@mkdir -p $(DIST)
	$(CC) $(BOF_CFLAGS) -o $@ $<
	@echo "[+] BOF: $@ ($$(stat -c%s $@) bytes)"

clean:
	rm -rf $(DIST)
