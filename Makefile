.PHONY: run build test docker-up docker-down deploy

run:
	go run ./cmd/server

build:
	go build -o bin/aicq ./cmd/server

test:
	go test -v ./...

docker-up:
	docker-compose up --build

docker-down:
	docker-compose down

deploy:
	fly deploy
