FROM python:3.12-slim
RUN useradd --system --uid 10001 app && mkdir -p /app/data && chown -R app /app
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY agentsec /app/agentsec
COPY app /app/app
COPY data /app/data
USER app
EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
