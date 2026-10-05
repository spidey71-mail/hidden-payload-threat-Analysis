FROM python:3.12-slim

# Create a non-root analysis user
RUN useradd --create-home --shell /usr/sbin/nologin analyzer

WORKDIR /sandbox

# Install Python dependencies
COPY analyzer/requirements.txt /tmp/requirements.txt

RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Copy analyzer
COPY analyzer/analyzer.py /sandbox/analyzer.py
COPY analyzer/extractors.py /sandbox/extractors.py

# Create isolated working directories
RUN mkdir -p /sandbox/input /sandbox/output \
    && chown -R analyzer:analyzer /sandbox

# Never run the analyzer as root
USER analyzer

ENTRYPOINT ["python", "/sandbox/analyzer.py"]