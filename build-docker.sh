#!/bin/bash

# Set the image name and tag
IMAGE_NAME="rivian-prometheus"
TAG="latest"

# Build the Docker image
echo "Building Docker image: $IMAGE_NAME:$TAG"
docker build -t $IMAGE_NAME:$TAG .

# Output success message
if [ $? -eq 0 ]; then
    echo "Docker image $IMAGE_NAME:$TAG built successfully."
else
    echo "Failed to build Docker image $IMAGE_NAME:$TAG."
    exit 1
fi