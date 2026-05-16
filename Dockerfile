FROM node:20-alpine

RUN apk add --no-cache openssl

WORKDIR /app
COPY package.json ./
COPY config ./config
COPY docs ./docs
COPY samples ./samples
COPY scripts ./scripts
COPY src ./src
COPY test ./test

EXPOSE 9443

CMD ["node", "src/ric-server.js"]
