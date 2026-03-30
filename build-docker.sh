#!/bin/bash

# Docker build and push script

set -e

IMAGE_NAME="bot53"
VERSION="${1:-latest}"
REGISTRY="${2:-docker.io}"

echo "Building BOT53 Docker image..."
docker build -t ${IMAGE_NAME}:${VERSION} .

if [[ "$REGISTRY" != "local" ]]; then
    echo "Tagging image..."
    docker tag ${IMAGE_NAME}:${VERSION} ${REGISTRY}/${IMAGE_NAME}:${VERSION}
    
    echo "Pushing to registry..."
    docker push ${REGISTRY}/${IMAGE_NAME}:${VERSION}
    
    if [[ "$VERSION" == "latest" ]]; then
        echo "Tagging as latest..."
        docker tag ${IMAGE_NAME}:${VERSION} ${REGISTRY}/${IMAGE_NAME}:latest
        docker push ${REGISTRY}/${IMAGE_NAME}:latest
    fi
fi

echo "Build complete!"