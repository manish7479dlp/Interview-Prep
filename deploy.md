#!/bin/bash

# === CONFIGURATION ===
REPO_URL="https://github.com/your-username/your-repo.git"
BRANCH_NAME="your-branch-name"
APP_DIR="vite-react-app"
IMAGE_NAME="vite-react-image"
CONTAINER_NAME="vite-react-container"
PORT=3000  # Change to 80 if you're using port 80 in Dockerfile

# === CLEANUP OLD FOLDER ===
if [ -d "$APP_DIR" ]; then
  echo "Removing existing app directory..."
  rm -rf "$APP_DIR"
fi

# === CLONE BRANCH ===
echo "Cloning branch '$BRANCH_NAME' from '$REPO_URL'..."
git clone --branch "$BRANCH_NAME" "$REPO_URL" "$APP_DIR"

# === CHANGE DIRECTORY ===
cd "$APP_DIR" || exit 1

# === BUILD DOCKER IMAGE ===
echo "Building Docker image '$IMAGE_NAME'..."
docker build -t "$IMAGE_NAME" .

# === STOP AND REMOVE EXISTING CONTAINER IF ANY ===
if docker ps -a --format '{{.Names}}' | grep -Eq "^${CONTAINER_NAME}\$"; then
  echo "Stopping and removing existing container..."
  docker stop "$CONTAINER_NAME"
  docker rm "$CONTAINER_NAME"
fi

# === RUN DOCKER CONTAINER ===
echo "Running Docker container '$CONTAINER_NAME'..."
docker run -d -p "$PORT":80 --name "$CONTAINER_NAME" "$IMAGE_NAME"

echo "✅ App is running at http://localhost:$PORT"
