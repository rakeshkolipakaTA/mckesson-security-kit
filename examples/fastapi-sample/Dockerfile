FROM python:3.9-slim
ENV APP_SECRET=hunter2-super-secret-value-123 AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYzZkq9AbCdEf
WORKDIR /app
ADD requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
ADD app /app/app
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
