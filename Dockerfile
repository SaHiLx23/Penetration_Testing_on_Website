# Use an official Python image with Debian support
FROM python:3.11

# Install necessary system dependencies
RUN apt-get update && apt-get install -y traceroute

# Set the working directory inside the container
WORKDIR /app

# Copy all project files into the container
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port Render uses
ENV PORT=10000
EXPOSE 10000

# Run the Flask app
CMD ["python", "app.py"]
