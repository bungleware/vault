.PHONY: run dev build test clean migrate sqlc-generate frontend-build frontend-dev build-all

# backend (live-reload) and frontend dev server concurrently
dev:
	@trap 'kill 0' SIGINT; \
	go tool wgo run -xdir tmp,frontend,data,migrations,bin,.git,.claude -file .sql ./cmd/server/main.go & \
	cd frontend && bun run dev & \
	wait

# backend-dev:
# 	go tool wgo run -xdir tmp,frontend,data,migrations,bin,.git,.claude -file .sql ./cmd/server/main.go

# frontend-dev:
# 	cd frontend && bun run dev

frontend-build:
	cd frontend && bun run build

backend-build: frontend-build
	go build -o server cmd/server/main.go

build: frontend-build backend-build

sqlc-generate:
	sqlc generate

clean:
	rm -rf bin/ data/

