# supply-chain-guard - official image (published to ghcr.io/homeofe/supply-chain-guard)
#
# Multi-stage build: the builder compiles TypeScript and packs the npm tarball,
# the runtime stage installs that tarball globally and runs as a non-root user.
#
# Note: the builder runs `npx tsc` directly instead of `npm run build` because
# the prebuild gates (check:changelog, check:version-sync, check:handoff,
# check:feed) validate repo files (CHANGELOG.md, .ai/handoff, feed.json) that
# are intentionally not copied into the image context.

FROM node:20-alpine AS builder

WORKDIR /build

COPY package*.json ./
# --ignore-scripts: the "prepare" lifecycle script (tsc) would run here, but
# tsconfig.json/src are not in this layer yet; the explicit RUN npx tsc below
# does the compile. Caught by the v5.5.0 verification gate (docker build
# failed at this layer).
RUN npm ci --ignore-scripts

COPY tsconfig.json ./
COPY src ./src
RUN npx tsc

# LICENSE / README / action.yml / socket.yml / policy-schema.json are part of
# the published npm package ("files" in package.json), so include them in the
# tarball too. "prepare" (tsc) IS defined since v5.5.0 and would recompile
# during npm pack - dist/ already exists, so skip lifecycle scripts entirely.
COPY LICENSE README.md action.yml socket.yml policy-schema.json ./
RUN npm pack --ignore-scripts --pack-destination /tmp

FROM node:20-alpine

# unzip extracts .vsix archives in the VS Code extension scanner path; zip is
# used by tests and kept for parity with the devcontainer.
RUN apk add --no-cache zip unzip

COPY --from=builder /tmp/supply-chain-guard-*.tgz /tmp/
RUN npm install -g /tmp/supply-chain-guard-*.tgz && rm -f /tmp/supply-chain-guard-*.tgz

# Run as a non-root user. /scan is the conventional mount point:
#   docker run --rm -v ${PWD}:/scan ghcr.io/homeofe/supply-chain-guard scan /scan
RUN addgroup -S scg && adduser -S scg -G scg && mkdir -p /scan && chown scg:scg /scan
USER scg
WORKDIR /scan

ENTRYPOINT ["supply-chain-guard"]
CMD ["--help"]
