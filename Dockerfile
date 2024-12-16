FROM python:3.11-alpine

WORKDIR /app

RUN apk add --no-cache npm==10.9.1-r0 && \
    rm -rf /var/cache/apk/* && \
    pip install --no-cache-dir poetry==1.8.4

COPY pyproject.toml poetry.lock ./

COPY package.json package-lock.json ./

COPY . .

RUN npm install && \
    poetry config virtualenvs.create false && \
    poetry install --no-root --no-interaction --no-ansi && \
    scripts/fix_mermaid_dompurify.sh

COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
