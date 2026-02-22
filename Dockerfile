FROM docker.io/oven/bun:latest AS frontend-builder

RUN apt-get update && apt-get install -y \
    libcairo2-dev libpango1.0-dev libjpeg-dev libgif-dev librsvg2-dev libexpat1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/frontend
COPY frontend/bun.lock frontend/package.json ./
RUN --mount=type=cache,target=/root/.bun/install/cache \
    bun install --frozen-lockfile
COPY frontend/ ./
RUN bun run build

FROM docker.io/library/golang:1.25-alpine AS backend-builder

ARG GIT_COMMIT=unknown

RUN apk add --no-cache git sqlite gcc musl-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download && go mod verify
COPY . .
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    cd cmd/server && \
    CGO_ENABLED=1 \
    go build -ldflags="-w -s -X main.CommitSHA=${GIT_COMMIT}" \
    -o ../../bin/vault-server

FROM docker.io/library/alpine:latest

RUN apk add --no-cache ca-certificates ffmpeg sqlite wget && \
    addgroup -g 1000 vault && \
    adduser -D -u 1000 -G vault vault

USER 1000:1000
WORKDIR /app

COPY --from=backend-builder /app/bin/vault-server .
COPY --from=backend-builder /app/frontend/dist ./frontend/dist
COPY --from=backend-builder /app/migrations ./migrations

VOLUME /app/data
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/api/health || exit 1

CMD ["./vault-server"]