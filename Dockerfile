FROM golang:1.10.1-alpine3.7 as build
RUN apk add --no-cache gcc git musl-dev
ARG COMMIT
RUN go get -u github.com/Masterminds/glide
RUN mkdir -p /go/src/github.com/coinstack/coinstackd
WORKDIR /go/src/github.com/coinstack/coinstackd
COPY . .
RUN glide install
RUN go build -ldflags "-linkmode external -extldflags -static -X main.appBuild=${COMMIT}" -a -o coinstackd .

FROM scratch
COPY --from=build /go/src/github.com/coinstack/coinstackd/coinstackd /coinstackd
EXPOSE 28333
EXPOSE 3000
VOLUME /.coinstackd
CMD ["/coinstackd"]
