#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

# Step 1: Log in to Hugging Face
echo "Logging into Hugging Face..."
huggingface-cli login || { echo "Login failed. Exiting."; exit 1; }

# Step 2: Create a new Space
SPACE_NAME="secure-data-system"
echo "Creating a new Space: $SPACE_NAME..."
huggingface-cli repo create "$SPACE_NAME" --type space || { echo "Failed to create Space. Exiting."; exit 1; }

# Step 3: Clone the Space repository
REPO_URL="https://huggingface.co/spaces/YOUR_USERNAME/$SPACE_NAME"
echo "Cloning the Space repository: $REPO_URL..."
git clone "$REPO_URL" || { echo "Failed to clone repository. Exiting."; exit 1; }

# Step 4: Copy files and prepare for deployment
echo "Copying files to the repository..."
cp -r {Dockerfile,requirements.txt,app.py,secure_data_system.py} "$SPACE_NAME/" || { echo "Failed to copy files. Exiting."; exit 1; }
cd "$SPACE_NAME" || { echo "Failed to change directory to $SPACE_NAME. Exiting."; exit 1; }

# Step 5: Commit and push changes
echo "Adding files to Git..."
git add . || { echo "Git add failed. Exiting."; exit 1; }
echo "Committing changes..."
git commit -m "Initial deployment" || { echo "Git commit failed. Exiting."; exit 1; }
echo "Pushing changes to Hugging Face..."
git push || { echo "Git push failed. Exiting."; exit 1; }

echo "Deployment to Hugging Face completed successfully."
