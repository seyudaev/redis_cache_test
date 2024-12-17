FROM golang:1.19.2 AS build-stage
WORKDIR /go/src
COPY src/*.go src/go.mod src/go.sum ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /go/bin/app

FROM debian
EXPOSE 8089
COPY *.crt app.key ./
COPY --from=build-stage go/bin/ .
CMD ./app