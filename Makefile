.PHONY: sand

sand:
	GOPATH="$(PWD)" && export GOPATH && go build -o build/sand ./sand.go
