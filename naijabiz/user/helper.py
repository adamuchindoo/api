import random
from django.contrib.auth import get_user_model
import os
import uuid
from ninja.files import UploadedFile
from django.core.files.storage import default_storage
from django.conf import settings
from django.core.exceptions import ValidationError
from ninja.errors import HttpError

# Define allowed image formats
ALLOWED_IMAGE_FORMATS = [".jpg", ".jpeg", ".png", ".gif", ".pdf"]


def generate_unique_username():
    User = get_user_model()
    while True:
        # Generate a random 10-digit number
        username = str(
            random.randint(10**9, 10**10 - 1)
        )  # Generates a number between 1000000000 and 9999999999
        # Check if the username is unique
        if not User.objects.filter(username=username).exists():
            return username


def generate_unique_filename(instance, filename):
    # Extract the file extension
    ext = os.path.splitext(filename)[1]
    # Generate a unique name using UUID
    unique_name = f"{uuid.uuid4()}{ext}"
    return os.path.join("selfie/", unique_name)


def save_uploaded_file(file: UploadedFile, subdirectory: str) -> str:
    """
    Save an uploaded file to the specified subdirectory with a unique name.
    Validates that the file is an image with an allowed format.
    Returns the relative path to the saved file.
    """
    # Extract the file extension
    ext = os.path.splitext(file.name)[1].lower()  # Convert to lowercase for consistency

    # Validate the file format
    if ext not in ALLOWED_IMAGE_FORMATS:
        raise HttpError(
            400,
            f"Unsupported file format. Allowed formats are: {', '.join(ALLOWED_IMAGE_FORMATS)}",
        )

    # Generate a unique name for the file
    unique_name = f"{uuid.uuid4()}{ext}"
    file_path = os.path.join(subdirectory, unique_name)
    full_path = os.path.join(settings.MEDIA_ROOT, file_path)

    # Ensure the directory exists
    os.makedirs(os.path.dirname(full_path), exist_ok=True)

    # Write the file to the media directory
    with open(full_path, "wb+") as destination:
        for chunk in file.chunks():
            destination.write(chunk)

    return file_path


def save_uploaded_file_x(file: UploadedFile, subdirectory: str) -> str:
    """
    Save an uploaded file to the specified subdirectory with a unique name.
    Returns the relative path to the saved file.
    """
    ext = os.path.splitext(file.name)[1]
    unique_name = f"{uuid.uuid4()}{ext}"
    file_path = os.path.join(subdirectory, unique_name)
    full_path = os.path.join(settings.MEDIA_ROOT, file_path)

    # Ensure the directory exists
    os.makedirs(os.path.dirname(full_path), exist_ok=True)

    # Write the file to the media directory
    with default_storage.open(full_path, "wb+") as destination:
        for chunk in file.chunks():
            destination.write(chunk)

    return file_path
