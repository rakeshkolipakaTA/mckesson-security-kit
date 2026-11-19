FROM python:3.12.8-slim
ENV PYTHONUNBUFFERED=1 DASHBOARD_DB=/data/dashboard.db
COPY server.py /app/server.py
RUN useradd -r -u 10001 dash && mkdir /data && chown dash /data
USER dash
VOLUME /data
EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8090/health')"
CMD ["python", "/app/server.py"]
