FROM node:22-alpine

# Install build dependencies
RUN apk add --no-cache python3 make g++ wget

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig*.json ./
COPY packages/qvl/package*.json ./packages/qvl/
COPY packages/tunnel/package*.json ./packages/tunnel/
COPY packages/demo/package*.json ./packages/demo/

# Install dependencies
RUN npm ci

# Copy source code
COPY packages/qvl/ ./packages/qvl/
COPY packages/tunnel/ ./packages/tunnel/
COPY packages/demo/ ./packages/demo/

# Build packages
RUN npm run build

# Change to demo directory
WORKDIR /app/packages/demo

# Expose port
EXPOSE 3001

# Start the demo server
CMD ["node", "../../node_modules/tsx/dist/cli.mjs", "server.ts"]
