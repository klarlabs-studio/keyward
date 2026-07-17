# Builds the two binaries the demo needs — the zero-knowledge sync server and the
# passbook CLI (used by the seeder to mint a real sealed demo vault). One image,
# both binaries + curl, so the same image runs the server and the seed job.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p proctor-sync-server -p passbook-cli

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/proctor-sync-server /usr/local/bin/
COPY --from=build /src/target/release/passbook /usr/local/bin/
COPY demo/seed.sh /usr/local/bin/seed.sh
RUN chmod +x /usr/local/bin/seed.sh
