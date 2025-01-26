# Architecture

This document outlines the architecture of the AI Nutrition-Pro application.

## Containers Context diagram

```mermaid
C4Container
    title Container diagram for AI Nutrition-Pro

    Container_Boundary(c0, "AI Nutrition-Pro") {
        Container(api_gateway, "API Gateway", "Kong", "Authentication of clients, filtering of input, rate limiting")
        Container(app_control_plane, "Web Control Plane", "Golang, AWS Elastic Container Service", "Provides control plane to onboard and manage clients, configuration and check billing data")
        ContainerDb(control_plan_db, "Control Plane Database", "Amazon RDS", "Stores all data related to control plan, tenants, billing")
        Container(backend_api, "API Application", "Golang, AWS Elastic Container Service", "Provides AI Nutrition-Pro functionality via API")
        ContainerDb(api_db, "API database", "Amazon RDS", "Stores dietitian' content samples, request and responses to LLM.")
        Person(admin, "Administrator", "Administrator of AI Nutrition-Pro application")
    }

    System_Ext(mealApp, "Meal Planner", "Application to create diets by dietitians")

    System_Ext(chatgpt, "ChatGPT-3.5", "LLM")

    Rel(mealApp, api_gateway, "Uses for AI content generation", "HTTPS/REST")
    Rel(api_gateway, backend_api, "Uses for AI content generation", "HTTPS/REST")
    Rel(admin, app_control_plane, "Configure system properties")
    Rel(backend_api, chatgpt, "Utilizes ChatGPT for LLM-featured content creation", "HTTPS/REST")

    Rel(app_control_plane, control_plan_db, "read/write data", "TLS")
    Rel(backend_api, api_db, "read/write data", "TLS")
```

### External systems and persons

| Name | Type | Description | Responsibilities |
| --- | --- | --- | --- |
| Meal Planner application | External system, web application | One of many Meal Planner applications that can be integrated with AI Nutrition-Pro. It connects to AI Nutrition-Pro using REST and HTTPS. | - uploads samples of dietitians' content to AI Nutrition-Pro <br/> - fetches AI generated results, e.g. diet introduction, from AI Nutrition-Pro |
|  ChatGPT-3.5 | External system, API | It's OpenAI product, an LLM solution | It will be used to generate content based on provided samples. |

### AI Nutrition-Pro container context systems and persons

| Name | Type | Description | Responsibilities |
| --- | --- | --- | --- |
| Web Control Plane | Internal system, Web application | It's written using Golang and deployed as Docker container into AWS Elastic Container Service. It uses Control Plane Database to store data. It's used in 3 roles: Administrator, App Onboarding Manager, and Meal Planner application manager. | Provide control plane to onboard and manage clients, configuration and check billing data |
| Control Plane Database | Internal database, Amazon RDS instance | Database | storing data for Web Control Plane |
| API Gateway | Internal system, API Gateway | Kong API Gateway | - authentication <br> - rate limiting <br> - filtering of input |
| API Application | Internal system, API application | It's written using Golang and deployed as Docker container into AWS Elastic Container Service | Provides AI Nutrition-Pro functionality via API. |
| API database | Internal database, Amazon RDS instance | Stored data: samples of dietitians' content, requests, and responses to LLM. | Storing data for API Application |
| Administrator | Internal Person | Administrator of AI Nutrition-Pro application. | - manage server configuration <br> - resolve problems <br> |

### Security

1. Authentication with Meal Planner applications - each has individual API key.
2. Authorization of Meal Planner applications - API Gateway has ACL rules that allow or deny certain actions.
3. Encrypted network traffic - network traffic between Meal Planner applications and API Gateway is encrypted using TLS.
