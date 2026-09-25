# supply-chain-guard - official image (published to ghcr.io/homeofe/supply-chain-guard)
#
# Multi-stage build: the builder compiles TypeScript and packs the npm tarball,
# the runtime stage installs that tarball with npm ci, pinned to the repository's
# package-lock.json, and runs as a non-root user.
#
# Note: the builder runs `npx tsc` directly instead of `npm run build` because
# the prebuild gates (check:aahp, check:feed, check:handoff,
# check:feed) validate repo files (CHANGELOG.md, .ai/handoff, feed.json) that
# are intentionally not copied into the image context.
#
# Base image pinning: both stages pin node:24-alpine by its multi-arch LIST
# (image index) digest so a compromised or re-pushed tag on Docker Hub cannot
# silently change what we build and ship. The digest is refreshed DELIBERATELY,
# not implicitly: dependabot's docker ecosystem (.github/dependabot.yml) opens
# a weekly PR when a newer node:24-alpine digest exists, and that PR is the
# only sanctioned way to bump it. Resolve manually with:
#   docker buildx imagetools inspect node:24-alpine
# (the top-level "Digest:" line is the list digest FROM needs).

FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS builder

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
RUN npm pack --ignore-scripts --pack-destination /tmp && mv /tmp/supply-chain-guard-*.tgz /tmp/supply-chain-guard.tgz

# The runtime install is pinned to this repository's package-lock.json. It used
# to be `npm install -g <tarball>`, which resolved the runtime dependencies from
# the registry by their semver range at image build time: `commander@^14` meant
# whatever 14.x was newest that day, never checked against the lockfile CI
# tested (OpenSSF Scorecard Pinned-Dependencies, code-scanning alert 4). The
# lockfile written here records the tarball's sha512 and copies every runtime
# entry of package-lock.json with its integrity, so the runtime stage's npm ci
# installs exactly those bytes or fails. The same generator drives the
# clean-room install in scripts/validate-package.sh on every CI lane.
COPY scripts/clean-room-lockfile.mjs ./scripts/
RUN node scripts/clean-room-lockfile.mjs /tmp/supply-chain-guard.tgz /opt/supply-chain-guard

FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1

# unzip extracts .vsix archives in the VS Code extension scanner path; zip is
# used by tests and kept for parity with the devcontainer.
RUN apk add --no-cache zip unzip

# The tarball goes to the same path it had in the builder, because the lockfile
# refers to it by relative path from /opt/supply-chain-guard.
COPY --from=builder /tmp/supply-chain-guard.tgz /tmp/supply-chain-guard.tgz
COPY --from=builder /opt/supply-chain-guard /opt/supply-chain-guard
# --ignore-scripts: this is the last npm invocation in the image and it runs as
# ROOT, before USER scg. The tarball declares no install lifecycle script, and
# scripts/validate-package.sh proves the same tarball installs cleanly with the
# flag on every CI lane, so nothing is lost by refusing to run any.
RUN cd /opt/supply-chain-guard \
 && npm ci --ignore-scripts --no-audit --no-fund \
 && npm cache clean --force \
 && rm -f /tmp/supply-chain-guard.tgz
ENV PATH=/opt/supply-chain-guard/node_modules/.bin:$PATH

# Run as a non-root user. /scan is the conventional mount point:
#   docker run --rm -v ${PWD}:/scan ghcr.io/homeofe/supply-chain-guard scan /scan
RUN addgroup -S scg && adduser -S scg -G scg && mkdir -p /scan && chown scg:scg /scan
USER scg
WORKDIR /scan

ENTRYPOINT ["supply-chain-guard"]
CMD ["--help"]
