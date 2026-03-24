# Flamix deployment

This repo supports a self-hosted deployment model.

## What is containerized

- `server/` is containerized in a production-like image.
- The built-in web/admin UI is served by the same server container.

## What is not containerized

- `app/` is a DearPyGUI desktop application.
- It is not a good fit for a generic Linux container because it expects a real desktop session and local GUI access.
- For admin workflows, use the server web UI from the container.
- For a desktop operator workflow, run `app/run.py` locally and point it at the server URL.

## Files

- [Dockerfile.server](../Dockerfile.server)
- [docker-compose.yml](../docker-compose.yml)
- [.env.example](../.env.example)

## Host layout

The compose setup binds these directories from the host:

- `data/` -> `/var/lib/flamix/data`
- `certs/` -> `/var/lib/flamix/certs`
- `logs/` -> `/var/log/flamix`

Keep all three directories on the host if you want stable state across restarts.
The container logs still go to `docker compose logs`; the mounted `logs/` directory is there for persisted artifacts or later file-based logging.

## Quick start

1. Create the host directories.

```bash
mkdir -p data certs logs
```

2. Create your local environment file.

```bash
cp .env.example .env
```

3. Build and start the server stack.

```bash
docker compose up -d --build
```

4. Check that the container is healthy.

```bash
docker compose ps
docker compose logs -f server
```

5. Open the built-in web/admin UI.

- `https://127.0.0.1:8080`

On first boot, the server generates TLS material inside the persistent `certs/` volume. Because it is self-signed, the browser will warn until you trust the CA or replace the certificate story with your own PKI.

## Runtime ports

- `8443` is the client/server protocol port.
- `8080` is the built-in admin web UI.

If you place this behind a reverse proxy later, keep the container ports unchanged and proxy only what you need.

## Environment variables

The container entrypoint reads these variables:

- `FLAMIX_SERVER_HOST`
- `FLAMIX_SERVER_PORT`
- `FLAMIX_WEB_HOST`
- `FLAMIX_WEB_PORT`
- `FLAMIX_WEB_DISABLED`
- `FLAMIX_DB_PATH`
- `FLAMIX_CERT_DIR`
- `FLAMIX_LOG_DIR`

Defaults are already set in [`.env.example`](../.env.example).

## Manual run

If you do not want Compose, build the image and run it directly:

```bash
docker build -f Dockerfile.server -t flamix/server:local .
docker run --rm \
  -p 8443:8443 \
  -p 8080:8080 \
  -v "$(pwd)/data:/var/lib/flamix/data" \
  -v "$(pwd)/certs:/var/lib/flamix/certs" \
  -v "$(pwd)/logs:/var/log/flamix" \
  --env-file .env \
  flamix/server:local
```

## Desktop GUI story

The desktop GUI remains a local application:

1. Start the server container.
2. Launch `app/run.py` on an admin workstation.
3. Point the GUI at `https://HOST:8080`.

That is the supported story for now. It avoids pretending that a desktop window can be containerized in the same way as the server.
