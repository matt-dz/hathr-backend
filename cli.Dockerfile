FROM --platform=$BUILDPLATFORM golang:alpine AS build
WORKDIR /app
COPY . .
RUN apk update && apk add make --no-cache
RUN make build-cli

FROM alpine:latest
WORKDIR /app
RUN apk update && apk add tzdata --no-cache
COPY --from=build /app/bin/hathr-cli /app/hathr-cli
ENTRYPOINT ["/app/hathr-cli"]
CMD [ "--help" ]
