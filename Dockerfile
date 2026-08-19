FROM apache/airflow:2.9.1-python3.10
# Copy requirements and install
COPY requirements.txt /requirements.txt
RUN pip install --no-cache-dir -r /requirements.txt
