FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py .

# Expose port 5000
EXPOSE 5000

# Warning label
LABEL description="Vulnerable web application for security testing - DO NOT USE IN PRODUCTION"
LABEL vulnerabilities="SQL Injection, XSS"

# Run the application
CMD ["python", "app.py"]
