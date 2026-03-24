.PHONY: build test bench clean run

build:
	go build -o bin/prompt-firewall .

test:
	go test ./...

bench:
	go test -bench=. -benchmem ./...

run: build
	./bin/prompt-firewall --listen :8080

clean:
	rm -rf bin/ prompt-firewall *.test *.out
