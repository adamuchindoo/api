#!/bin/bash

# Define the container name
CONTAINER_NAME=naijabiz-backend

# Define the base directory inside the container and locally
CONTAINER_DIR=/app
LOCAL_DIR=./

# List all apps in your project (replace with your actual app names)
APPS=("user" )

# Loop through each app and copy its migrations folder
for APP in "${APPS[@]}"; do
  echo "Copying migrations for app: $APP"
  
  # Create the local migrations folder if it doesn't exist
  mkdir -p "$LOCAL_DIR/$APP/migrations"
  
  # Copy the migrations folder from the container to your local machine
  docker cp "$CONTAINER_NAME:$CONTAINER_DIR/$APP/migrations/" "naijabiz/$LOCAL_DIR/$APP/"
done
#permission chmod +x sync_migrations.sh
#code to run is naijabiz/sync_migrations.sh
echo "All migration files copied successfully!"

