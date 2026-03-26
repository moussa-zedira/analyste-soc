FROM python:3.13-slim

WORKDIR /app

COPY apps/agent/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY apps/ apps/

CMD ["python", "-m", "apps.agent", "simulator", "--eps", "3"]
