#!/usr/bin/env bash

# Check if podman or docker command exists
CONTAINER_CLI="docker"
if command -v podman &> /dev/null; then
    CONTAINER_CLI="podman"
elif command -v docker &> /dev/null; then
    CONTAINER_CLI="docker"
else
    echo "Error: podman or docker command not found. Please visit the official website to download and install."
    exit 1
fi

# Check if the user has docker group permissions
if [ "$CONTAINER_CLI" == "docker" ]; then
    if ! groups | grep -q "\bdocker\b"; then
        CONTAINER_CLI="sudo docker"
    fi
fi

# Execute the build command
CMD="${CONTAINER_CLI} run --rm -it -v \"$(pwd)\":/home/rust/src ghcr.io/rust-cross/rust-musl-cross:x86_64-musl cargo build --release"

echo "Executing the build command:"
echo "$CMD"
eval "$CMD"
