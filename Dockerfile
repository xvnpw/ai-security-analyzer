FROM python:3.11-alpine

WORKDIR /app

RUN apk add --no-cache npm==10.9.1-r0 && \
    rm -rf /var/cache/apk/* && \
    pip install --no-cache-dir poetry==1.8.4

COPY pyproject.toml poetry.lock ./

COPY package.json package-lock.json ./

COPY . .

RUN ./build.sh

COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
