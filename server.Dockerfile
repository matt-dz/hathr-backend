FROM --platform=$BUILDPLATFORM golang:alpine AS build
WORKDIR /app
COPY . .
RUN apk update && apk add make
RUN make build-server

FROM alpine:latest
ENV ENV=PROD
WORKDIR /app
COPY --from=build /app/bin/hathr-server /app/hathr-server
RUN apk update && apk add tzdata --no-cache
EXPOSE 8080
ENTRYPOINT ["/app/hathr-server"]
