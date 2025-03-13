# Transaction API

## Overview

Transaction API is microservice that will be used to process transactions. Customers (e.g. banks) will call it to send and receive money from the scheme.

## Architecture

```mermaid
flowchart LR
    A[Bank] -->|Send transaction <br/>REST/HTTPS| B(API Gateway<br/>Kong)
    B --> C(Transaction API<br/>Python microservice)
    C --> |Store| D(Database<br/>Postgresql)
    C --> E(Queue<br/>RabbitMQ)
    E --> F(Gateway<br/>Python microservice)
    F --> |XML/HTTPS| G(Scheme)
    B --> |Authenticate bank| H(Identity Provider<br/>OAuth2, keyclock)
    B --> |Authorize access| I(Authorization rules)
```


