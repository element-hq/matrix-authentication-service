
# Build Node.js app
FROM --platform=${BUILDPLATFORM} docker.io/library/node:22-bookworm AS builder

WORKDIR /syn2mas

COPY ./package.json ./package-lock.json ./tsconfig.json ./
COPY ./src ./src
RUN --network=default \
  npm ci

# Install the production dependencies for each architecture we support
FROM --platform=${BUILDPLATFORM} docker.io/library/node:22-bookworm AS deps

WORKDIR /deps/arm64

COPY ./package.json ./package-lock.json ./
# Remove the "prepare" script to avoid compiling typescript
RUN sed -i '/"prepare"/d' package.json
RUN --network=default \
  npm ci \
  --target_arch=amd64 \
  --target_platform=linux \
  --omit=dev

WORKDIR /deps/amd64

COPY ./package.json ./package-lock.json ./
# Remove the "prepare" script to avoid compiling typescript
RUN sed -i '/"prepare"/d' package.json
RUN --network=default \
  npm ci \
  --target_arch=x64 \
  --target_platform=linux \
  --omit=dev


# Runtime stage
FROM gcr.io/distroless/nodejs18-debian12:debug-nonroot

WORKDIR /syn2mas
COPY ./package.json ./package-lock.json ./
COPY --from=builder /syn2mas/dist ./dist

ARG TARGETARCH
COPY --from=deps /deps/${TARGETARCH}/node_modules ./node_modules

ENTRYPOINT ["/nodejs/bin/node", "--enable-source-maps", "/syn2mas/dist/index.js"]
