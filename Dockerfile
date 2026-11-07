# 单阶段构建：纯标准库，无 CGO。
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=docker" -o /out/scnet2api .

FROM alpine:3.20
RUN adduser -D -H -u 10001 app
USER app
WORKDIR /app
COPY --from=build /out/scnet2api /app/scnet2api
ENV SCNET2API_HOST=0.0.0.0 \
    SCNET2API_PORT=10088 \
    SCNET2API_DATA_PATH=/app/data/data.json
VOLUME ["/app/data"]
EXPOSE 10088
ENTRYPOINT ["/app/scnet2api"]
