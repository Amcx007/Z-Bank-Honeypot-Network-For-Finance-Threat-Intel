# Honeypot Network for Finance Threat Intelligence
**Project Code:** PRJN26-213  
**Student:** Abdul Mirsab C — 23BCCE096  
**Institution:** Yenepoya Institute of Arts, Science, Commerce and Management  

## Overview
A containerized deception platform simulating financial services 
infrastructure to attract, capture, and analyze real-world cyber 
attacks using the ELK Stack.

## Modules
- SSH Honeypot (port 2222)
- Services Honeypot — FTP, Telnet, MySQL, PostgreSQL, Redis
- Banking Portal (port 8080)
- Finance API (port 8081)
- ELK Stack — Elasticsearch + Logstash + Kibana

## Run
```bash
docker-compose up --build
```
- Banking Portal → http://localhost:8080  
- Kibana → http://localhost:5601