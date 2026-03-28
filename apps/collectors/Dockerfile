FROM python:3.12-slim

WORKDIR /app

# Install collector dependencies
COPY apps/collectors/requirements.txt /tmp/collectors-requirements.txt
RUN pip install --no-cache-dir -r /tmp/collectors-requirements.txt

# Copy collector code
COPY apps/__init__.py apps/__init__.py
COPY apps/collectors/ apps/collectors/

EXPOSE 514/udp 1514/tcp

CMD ["python", "-m", "apps.collectors", "syslog"]
