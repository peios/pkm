IMAGE  := pkm-kernel-builder
OUT    := $(CURDIR)/out
CCACHE := pkm-kernel-ccache

.PHONY: all image kernel shell clean clean-all

all: kernel

image:
	docker build -t $(IMAGE) .

kernel: image
	mkdir -p $(OUT)
	docker run --rm \
		-v $(OUT):/out \
		-v $(CCACHE):/ccache \
		$(IMAGE) \
		bash -c 'make LLVM=1 CC="ccache clang" -j$$(nproc) && cp arch/x86/boot/bzImage /out/ && make LLVM=1 modules_install INSTALL_MOD_PATH=/out'
	@echo ""
	@echo "Kernel image: $(OUT)/bzImage"
	@echo "Modules:      $(OUT)/lib/modules/"

shell: image
	docker run --rm -it -v $(CCACHE):/ccache $(IMAGE) bash

clean:
	rm -rf $(OUT)

clean-all: clean
	docker volume rm -f $(CCACHE)
