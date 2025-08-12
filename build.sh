#!/bin/bash

TIDY_FILE=".tidy"

if [ "$1" = "update" ] || [ ! -f "$TIDY_FILE" ]; then
	echo "Go mod tidy: fetching modules"
    go mod tidy
    touch "$TIDY_FILE"
fi

echo "Building..."
GOOS=linux GOARCH=arm64 CGO_ENABLED=0  go build -ldflags="-s -w" 
echo "Done :)"

if [ "$1" = "push" ]; then
	adb push groidproxy /data/local/tmp
	echo "Pushed to /data/local/tmp"
fi