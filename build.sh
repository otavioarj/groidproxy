GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o groidproxy -ldflags="-s -w" groidproxy.go
