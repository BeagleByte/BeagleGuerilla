# Use an official Python image as a base
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install dependencies
RUN pip install -r requirements.txt

# Copy application
COPY . .

# Expose the port
EXPOSE 5000

# Run the app
CMD ["waitress-serve", "--host=0.0.0.0", "--port=5000", "app:app"]