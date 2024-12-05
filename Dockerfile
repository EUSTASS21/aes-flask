FROM python

WORKDIR /app/backend

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY req.txt /app/backend/

RUN pip install -r req.txt

COPY . /app/backend/

EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]