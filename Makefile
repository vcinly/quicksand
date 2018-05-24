.PHONY: eth

eth:
	GOPATH="$(PWD)" && export GOPATH && go build -o build/eth ./eth.go
