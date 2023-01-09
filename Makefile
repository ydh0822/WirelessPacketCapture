NAME=WPC

all: deps build

deps:
	go get github.com/google/gopacket

build:
	go build -o ${NAME} main.go

clean:
	go clean
	rm ${NAME}