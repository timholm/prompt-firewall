.PHONY: build test clean

build:
	go build -o bin/prompt-firewall ./...

test:
	go test ./...

clean:
	rm -rf bin/
