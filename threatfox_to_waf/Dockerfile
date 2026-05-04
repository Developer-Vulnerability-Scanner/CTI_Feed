FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy script code
COPY . .

# Run the ingestion & export loop every hour
CMD ["python", "export_to_waf.py"]