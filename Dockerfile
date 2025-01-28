FROM python:3.11-alpine

WORKDIR /app

RUN pip install --no-cache-dir poetry==1.8.4

COPY pyproject.toml poetry.lock ./

COPY . .

RUN poetry config virtualenvs.create false && \
    poetry install --no-root --no-interaction --no-ansi

COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
