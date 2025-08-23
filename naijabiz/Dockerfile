# Use a slim version of Python 3.12 as the base image
FROM python:3.12-slim

# Set the working directory inside the container
WORKDIR /app

# Copy and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project into the container
COPY . .

# Collect static files
RUN python manage.py collectstatic --noinput


# Expose the port Daphne will serve on
EXPOSE 8000

# Start the ASGI server (Daphne) using the correct module path
CMD ["daphne", "-b", "0.0.0.0", "-p", "8000", "naijabiz.asgi:application"]
