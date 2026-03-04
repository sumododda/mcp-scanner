FROM cgr.dev/chainguard/node:latest-dev AS build

WORKDIR /app
COPY --chown=node:node package*.json .
RUN npm ci

COPY --chown=node:node . .
RUN npm run build

FROM cgr.dev/chainguard/node:latest

WORKDIR /app
COPY --from=build /app/build ./build
COPY --from=build /app/package.json .
EXPOSE 3000
ENV NODE_ENV=production
CMD ["build"]
