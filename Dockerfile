FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app
RUN apk add --no-cache curl
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/src/db/migrations ./src/db/migrations
COPY --from=builder /app/src/admin/ui ./src/admin/ui
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
EXPOSE 3000
CMD ["node", "dist/main.js"]
