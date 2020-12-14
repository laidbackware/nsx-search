#!/bin/bash

VERSION=$1
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

env GOOS=linux GOARCH=amd64 go build -o ${SCRIPT_DIR}/builds/nsxsearch-linux-${VERSION}

env GOOS=windows GOARCH=amd64 go build -o ${SCRIPT_DIR}/builds/nsxsearch-windows-${VERSION}

env GOOS=darwin GOARCH=amd64 go build -o ${SCRIPT_DIR}/builds/nsxsearch-darwin-${VERSION}
