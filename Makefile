.PHONY: all build bpf install clean

# 默认目标
all: bpf build

# 编译 BPF 程序
bpf:
	@echo "Compiling BPF programs..."
	@mkdir -p build
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
		-Iinclude -I/usr/include/bpf \
		-c bpf/tls_trace.bpf.c -o build/tls_trace.bpf.o
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
		-Iinclude -I/usr/include/bpf \
		-c bpf/http2_trace.bpf.c -o build/http2_trace.bpf.o
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
		-Iinclude -I/usr/include/bpf \
		-c bpf/l7_sniffer.bpf.c -o build/l7_sniffer.bpf.o
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
		-Iinclude -I/usr/include/bpf \
		-c bpf/log_collect.bpf.c -o build/log_collect.bpf.o
	@echo "BPF programs compiled."

# 编译 Go 二进制
build: bpf
	@echo "Building Go binary..."
	go build -o build/ebpf-probe ./cmd/probe/
	@echo "Build complete: build/ebpf-probe"

# 安装到 /usr/local/bin/
install: build
	@echo "Installing to /usr/local/bin/..."
	install -m 755 build/ebpf-probe /usr/local/bin/ebpf-probe
	@echo "Installation complete."

# 清理
clean:
	rm -rf build/
	@echo "Clean complete."

# ARM32 交叉编译
arm32:
	@echo "Cross-compiling for ARM32..."
	GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 \
		go build -o build/stb-ebpf-probe ./cmd/probe/
	@echo "ARM32 build complete."

# 测试
test:
	go test ./...

# 格式化
fmt:
	go fmt ./...

# 静态检查
vet:
	go vet ./...
