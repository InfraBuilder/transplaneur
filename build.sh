#!/bin/bash

# Get the current branch name
current_branch=$(git rev-parse --abbrev-ref HEAD)

if [ "$current_branch" == "main" ]; then
    # Get the latest Git tag
    bin_version=$(git describe --tags)
else
    # Use the branch name and commit SHA
    bin_version="${current_branch}:$(git rev-parse --short HEAD)"
fi

function build {
    platform="$1"
    os="$2"
    arch="$3"

    echo "Building for $platform"
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -ldflags "-X main.version=$bin_version" -o bin/transplaneur_${os}_${arch} main.go
}

case $1 in
    linux)
        build "Linux amd64" "linux" "amd64"
        ;;
    *)
        echo "Usage: $0 [linux]"
        ;;
esac