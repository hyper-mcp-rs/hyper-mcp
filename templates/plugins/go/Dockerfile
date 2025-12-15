FROM tinygo/tinygo:0.40.0 AS builder

WORKDIR /workspace
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN GOOS=wasip1 GOARCH=wasm tinygo build -no-debug -panic=trap -scheduler=none -o plugin.wasm

FROM scratch
WORKDIR /
COPY --from=builder /workspace/plugin.wasm /plugin.wasm
