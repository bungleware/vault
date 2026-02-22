# { vault }

A self-hosted streaming application for your work-in-progress music.

<img width="1208" height="852" alt="covers" src="docs/covers.webp" />

<details>
  <summary>More screenshots</summary>
  <img width="1252" height="896" alt="tracks" src="docs/tracks.webp" />
  <img width="1624" height="1056" alt="sharing" src="docs/sharing.webp" />
  <img width="1624" height="1056" alt="versions" src="docs/versions.webp" />
  <img width="1624" height="1056" alt="search" src="docs/search.webp" />
  <img width="1624" height="1056" alt="settings" src="docs/settings.webp" />
</details>

# About

This app is inspired by [untitled]. I wanted to create an open source alternative. I couldn't find anything similar, so I started this as a side project in Nov 2025.

# Main Features

- Store your audio projects
- Add other accounts in your instance via an invite link
- Share projects and tracks across users in the same instance
- Share your projects and tracks publicly with a link, with defined permissions (downloading, password protection)
- Organize your library in folders (can also nest them)
- Export and import your instance (zip backup)

# Setup

Requires Docker.

**Automated**

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/bungleware/vault/main/scripts/setup.sh)
```

This downloads `docker-compose.yml`, generates an `.env` with random secrets, and starts the container. An optional directory name can be passed as an argument (default: `vault`).

**Manual**

```bash
mkdir vault && cd vault
curl -o docker-compose.yml https://raw.githubusercontent.com/bungleware/vault/main/docker-compose.yml
curl -o .env https://raw.githubusercontent.com/bungleware/vault/main/.env.example
```

Edit `.env` and set `JWT_SECRET`, `SIGNED_URL_SECRET`, and `TOKEN_PEPPER` to random strings (e.g. `openssl rand -base64 32`), then:

```bash
docker compose up -d
```

The app will be available at `http://localhost:8080`.

# Build from source and Development

[See here](docs/DEVELOPMENT.md)

# Transparency

Part of this project was done with coding models (Opus, 5.3). Keeping the previous statement in mind, if you want to browse thorugh the repository and contribute please do so! I still feel the app's architecture can be improved massively.
