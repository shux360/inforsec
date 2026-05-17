FROM node:20-alpine AS build

WORKDIR /app

COPY package.json ./package.json
COPY src ./src
COPY scripts ./scripts
COPY samples ./samples
COPY test ./test
COPY ui/package.json ./ui/package.json
COPY ui/package-lock.json ./ui/package-lock.json
COPY ui/index.html ./ui/index.html
COPY ui/src ./ui/src

WORKDIR /app/ui

ARG VITE_DEMO_SERVER_URL=http://127.0.0.1:8080/demo/send
ARG VITE_DEMO_API_KEY=inforsec-demo-key
ENV VITE_DEMO_SERVER_URL=$VITE_DEMO_SERVER_URL
ENV VITE_DEMO_API_KEY=$VITE_DEMO_API_KEY

RUN npm install
RUN npm run build

FROM nginx:1.27-alpine

COPY --from=build /app/ui/dist /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]