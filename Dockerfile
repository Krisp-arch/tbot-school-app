# Use an official, lightweight Python image.
FROM python:3.9-slim

# Set the working directory inside the container to /app
WORKDIR /app

# Copy the dependencies file first. This is a Docker best practice
# that speeds up future builds.
COPY requirements.txt .

# Install the dependencies.
RUN pip install --no-cache-dir -r requirements.txt

# Copy your entire application code into the container.
COPY . .

# The command to run your application when the container starts.
# The command to run your application when the container starts.
# We bind to 0.0.0.0 and use the $PORT environment variable provided by Vercel.
CMD ["gunicorn", "--bind", "0.0.0.0:$PORT", "--workers", "1", "--threads", "8", "--timeout", "0", "app:app"]