# Use the official Python 3.10.14 slim image
FROM python:3.10.14-slim-bullseye

# Set working directory
WORKDIR /app

# Install dependencies
COPY ./requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . /app

# Expose port
EXPOSE 8000

# Set environment variables (will be overridden by Docker run command)
ENV PYTHONUNBUFFERED=1

# Run the FastAPI app with Uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
