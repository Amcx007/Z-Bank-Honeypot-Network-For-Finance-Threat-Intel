FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install paramiko
CMD ["python", "server.py"]