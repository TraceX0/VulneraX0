# Use a lightweight Python image
FROM python:3.10-slim

# Set the working directory
WORKDIR /app

# Copy only the necessary files
COPY dist/  .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port your app runs on (default Flask is 5000)
EXPOSE 5000

# Run the app
CMD ["python", "app.py"]