# Build from source

Requires Go 1.23+ and Bun.

```bash
git clone https://github.com/bungleware/vault
cd vault
cp .env.example .env
make build
./server
```

# Development

Requires Go 1.23+, Bun, and [wgo](https://github.com/bokwoon95/wgo) for live reload.

```bash
# Install wgo
go install github.com/bokwoon95/wgo@latest

# Install frontend dependencies
cd frontend && bun install && cd ..

cp .env.example .env
make dev
```

This starts the backend with live reload and the frontend dev server concurrently.

## Backend

Go application rooted at `internal/`. The entry point is `cmd/server/main.go`. Database queries are written in SQL under `internal/db/queries/` and compiled with [sqlc](https://sqlc.dev). Migrations live in `migrations/`.

## Frontend

React app under `frontend/`. Uses Bun as the package manager. Built with Vite, Tanstack Router, TailwindCSS, and Radix UI.

# Source Tree

```
vault/
├── cmd/server/         # Application entry point
├── frontend/           # React frontend
│   └── src/
│       ├── api/        # API client functions per domain
│       ├── components/ # Reusable UI components and modals
│       ├── contexts/   # React context providers (auth, audio player)
│       ├── hooks/      # Custom React hooks
│       ├── routes/     # Page components organized by route
│       └── types/      # TypeScript type definitions
├── internal/           # Go backend packages
│   ├── apperr/         # Application error types
│   ├── auth/           # Authentication logic (JWT, cookies, sessions)
│   ├── db/             # SQL queries and sqlc-generated database code
│   ├── fileutil/       # File handling utilities
│   ├── handlers/       # HTTP handlers grouped by domain
│   ├── httputil/       # HTTP response helpers and handler wrapper
│   ├── ids/            # ID generation
│   ├── logger/         # Structured logging
│   ├── middleware/     # HTTP middleware (auth, CSRF, security headers, signed URLs)
│   ├── models/         # Shared data models
│   ├── service/        # Business logic services
│   ├── storage/        # File storage abstraction
│   └── transcoding/    # Audio transcoding
├── migrations/         # SQLite migration files
├── scripts/            # Utility scripts
└── data/               # Runtime data (SQLite database and uploaded files)
```
