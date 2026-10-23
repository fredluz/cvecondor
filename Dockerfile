# cvecondor: one static binary in a small image. The build stage compiles it against musl; the runtime stage adds
# ca-certificates, openssh-client (the ssh collector) and gitleaks (secret detection, checksum-verified).
#
# Optional: --build-arg AGENT=<name> adds what a responder needs to work on your repos: git, and gh with git set to
# authenticate to GitHub through gh (so a GH_TOKEN in the responder's env is its git login).
#   AGENT=claude or AGENT=codex   also installs that agent CLI (Node + npm are added for it).
#   any other value               adds only git and gh. Your own agent CLI is yours to add: extend this image
#                                 (FROM cvecondor, then install it) and set `responder.command` to its argv.
# Log the CLI in with your own subscription (claude: `claude setup-token`, passed as CLAUDE_CODE_OAUTH_TOKEN; see
# README), never an API key.
FROM rust:1-alpine AS build

RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
# The responder's brief (agent/respond/*.md) is compiled into the binary.
COPY agent/respond ./agent/respond
# The agent in charge's rules (AGENTS.md) are compiled in: the reply relay starts every prompt with them.
COPY AGENTS.md ./
COPY src ./src
RUN cargo build --release --locked

FROM alpine:3.22

ARG GITLEAKS_VERSION=8.30.1
ARG TARGETARCH
ARG AGENT=""

RUN apk add --no-cache openssh-client ca-certificates \
 && arch="$(case "${TARGETARCH:-amd64}" in arm64) echo arm64 ;; *) echo x64 ;; esac)" \
 && cd /tmp \
 && wget -q "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${arch}.tar.gz" \
 && wget -q "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_checksums.txt" \
 && grep " gitleaks_${GITLEAKS_VERSION}_linux_${arch}.tar.gz\$" "gitleaks_${GITLEAKS_VERSION}_checksums.txt" | sha256sum -c - \
 && tar -xzf "gitleaks_${GITLEAKS_VERSION}_linux_${arch}.tar.gz" -C /usr/local/bin gitleaks \
 && mkdir -p /usr/share/licenses/gitleaks && tar -xzf "gitleaks_${GITLEAKS_VERSION}_linux_${arch}.tar.gz" -C /usr/share/licenses/gitleaks LICENSE \
 && rm -f /tmp/gitleaks_* \
 && if [ -n "$AGENT" ]; then apk add --no-cache git github-cli bash && git config --system credential.https://github.com.helper '!gh auth git-credential'; fi \
 && if [ "$AGENT" = claude ]; then apk add --no-cache nodejs npm && npm install -g --omit=dev @anthropic-ai/claude-code && npm cache clean --force; \
    elif [ "$AGENT" = codex ]; then apk add --no-cache nodejs npm && npm install -g --omit=dev @openai/codex && npm cache clean --force; fi

COPY --from=build /src/target/release/cvecondor /usr/local/bin/cvecondor
COPY agent/respond /usr/share/cvecondor/respond
COPY LICENSE NOTICE /usr/share/licenses/cvecondor/

ENV CVECONDOR_STATE_DIR=/data \
    CVECONDOR_CONFIG=/config/config.json
RUN addgroup -g 1000 cvecondor && adduser -D -u 1000 -G cvecondor cvecondor \
 && mkdir -p /data && chown cvecondor:cvecondor /data
VOLUME /data
USER cvecondor

ENTRYPOINT ["cvecondor"]
CMD ["run"]
