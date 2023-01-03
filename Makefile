CLIENT_BINARY_NAME=https-client
SERVER_BINARY_NAME=https-server

all: https-client https-server

stripped: https-client-stripped https-server-stripped

static: https-client-static https-server-static

static-and-stripped: https-client-static-and-stripped https-server-static-and-stripped

https-client:
	GOARCH=amd64 GOOS=linux go build -o ./bin/${CLIENT_BINARY_NAME} ./cmd/${CLIENT_BINARY_NAME}

https-server:
	GOARCH=amd64 GOOS=linux go build -o ./bin/${SERVER_BINARY_NAME} ./cmd/${SERVER_BINARY_NAME}

https-client-stripped:
	GOARCH=amd64 GOOS=linux CGO_ENABLED=1 go build -ldflags '-s' -o ./bin/${CLIENT_BINARY_NAME} ./cmd/${CLIENT_BINARY_NAME}

https-server-stripped:
	GOARCH=amd64 GOOS=linux CGO_ENABLED=1 go build -ldflags '-s' -o ./bin/${SERVER_BINARY_NAME} ./cmd/${SERVER_BINARY_NAME}

https-client-static:
	GOARCH=amd64 GOOS=linux CGO_ENABLED=0 go build -o ./bin/${CLIENT_BINARY_NAME} ./cmd/${CLIENT_BINARY_NAME}

https-server-static:
	GOARCH=amd64 GOOS=linux CGO_ENABLED=0 go build -o ./bin/${SERVER_BINARY_NAME} ./cmd/${SERVER_BINARY_NAME}

https-client-static-and-stripped:
	GOARCH=amd64 GOOS=linux CGO_ENABLED=0 go build -ldflags '-s' -o ./bin/${CLIENT_BINARY_NAME} ./cmd/${CLIENT_BINARY_NAME}

https-server-static-and-stripped:
	GOARCH=amd64 GOOS=linux CGO_ENABLED=0 go build -ldflags '-s' -o ./bin/${SERVER_BINARY_NAME} ./cmd/${SERVER_BINARY_NAME}

.PHONY: run build_and_run dep vet

run:
	./${BINARY_NAME}

build_and_run: build run

clean:
	go clean
	rm ./bin/${CLIENT_BINARY_NAME}
	rm ./bin/${SERVER_BINARY_NAME}

dep:
	go mod download

vet:
	go vet

