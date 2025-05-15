FROM python:3.11-slim

WORKDIR /function
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY handler.py .
ENV fprocess="python handler.py"
CMD ["fwatchdog"]

RUN pip install --no-cache-dir flask
ENV mode="http"
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libjpeg-dev zlib1g-dev && apt-get clean
