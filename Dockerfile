FROM --platform=$BUILDPLATFORM golang:alpine AS build
WORKDIR /app
COPY . .
RUN apk update && apk add make
RUN make build

FROM alpine:latest
ENV ENV=PROD
WORKDIR /app
COPY --from=build /app/bin/hathr /app/hathr
EXPOSE 8080
ENTRYPOINT ["/app/hathr"]
