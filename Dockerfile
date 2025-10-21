FROM python:3.12-slim
LABEL org.opencontainers.image.title="cognis-s3sniff"
LABEL org.opencontainers.image.source="https://github.com/cognis-digital/s3sniff"
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .
ENTRYPOINT ["s3sniff"]
