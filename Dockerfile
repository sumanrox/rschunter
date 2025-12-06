FROM python:3.11-slim

LABEL org.opencontainers.image.title="RSC Hunter"
LABEL org.opencontainers.image.description="High-performance mass vulnerability scanner for CVE-2025-55182"
LABEL org.opencontainers.image.version="2.0.0"
LABEL org.opencontainers.image.authors="Suman Roy"
LABEL org.opencontainers.image.licenses="MIT"

# Set working directory
WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir requests urllib3

# Copy application files
COPY rschunter.py .
COPY test_rschunter.py .
COPY README.md .

# Create volume mount point for targets and output
VOLUME ["/targets", "/output"]

# Run tests on build to ensure everything works
RUN python test_rschunter.py

# Set entrypoint
ENTRYPOINT ["python", "rschunter.py"]

# Default help command
CMD ["--help"]
