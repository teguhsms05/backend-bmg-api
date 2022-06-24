FROM python:3.9.7

WORKDIR /app

COPY requirements.txt /app

RUN pip install -r requirements.txt --no-cache-dir

COPY ./src .

# EXPOSE 5000

#CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
