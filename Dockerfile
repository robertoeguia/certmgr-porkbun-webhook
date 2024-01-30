FROM golang:1.21-alpine as BUILDER

COPY . /app

WORKDIR /app

RUN wget "https://github.com/upx/upx/releases/download/v4.2.2/upx-4.2.2-amd64_linux.tar.xz"; \
    tar -xvf "upx-4.2.2-amd64_linux.tar.xz";

RUN CGO_ENABLED=0 go build -ldflags '-w -s -extldflags "-static"' . ; \
    ./upx-4.2.2-amd64_linux/upx certmgr-porkbun-webhook;

FROM alpine:3

COPY --from=BUILDER /app/certmgr-porkbun-webhook /app/

WORKDIR /app

ENTRYPOINT [ "/app/certmgr-porkbun-webhook" ]