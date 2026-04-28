FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install flask
RUN mkdir -p /data /logs
CMD ["python", "app.py"]