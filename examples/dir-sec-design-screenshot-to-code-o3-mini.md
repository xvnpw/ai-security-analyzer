# Project Design Document for screenshot-to-code

This document details the design of screenshot-to-code – an open source tool that converts screenshots, design mockups, and even video recordings into functional code using AI. The system supports multiple technology stacks (HTML/Tailwind, HTML/CSS, React/Tailwind, Vue/Tailwind, Bootstrap, Ionic/Tailwind, and SVG) and integrates with several AI models (GPT-4, Claude, Gemini, and image generation models such as DALL-E 3/Flux Schnell).

---

# BUSINESS POSTURE

The primary business goal is to accelerate the transition from design to code by automating the coding of user interfaces based on visual inputs. The solution targets startups to large enterprises that want to reduce the turnaround time for prototyping web applications with high fidelity. Key priorities include:
- Rapid prototyping and iterative development.
- Support for multiple frontend stacks to cater to diverse customer requirements.
- Enabling side-by-side evaluation of generated results and continuous model integration.
- Offering a hosted version (with paid subscriptions) and an open source version.

Important business risks to address include:
- Dependence on third-party AI services and potential changes in API pricing, availability, or performance.
- Quality and correctness concerns in generated code that may require manual review.
- Potential misuse or exposure of sensitive API keys if not handled properly.
- Competitive risks from similar code generation services in the market.

---

# SECURITY POSTURE

Existing security controls and accepted risks include:
- security control: The backend is built with FastAPI and uses a CORS middleware configured to allow all origins (open for development). This is acceptable for initial testing but requires tightening in production.
- security control: API keys (OpenAI, Anthropic, Gemini, Replicate) are managed via environment variables (.env file) and are not stored permanently on the server. Keys provided through the settings dialog are retained only in the user’s browser.
- accepted risk: The current CORS policy and the immediate exposure of API keys on clients are acceptable during the prototyping phase.
- security control: Standard logging and error handling are implemented, and debugging artifacts can be enabled for development purposes.

Recommended high-priority security controls:
- Implement strict CORS policies and network security in production.
- Enforce input validation and sanitized processing for user-supplied URLs and images.
- Introduce robust authentication and authorization mechanisms (especially for hosted paid versions) to prevent unauthorized access.
- Use supply‐chain security measures for dependency management and regular vulnerability scanning.
- Encrypt sensitive data in transit using HTTPS for all external API calls.
- Monitor and rate-limit API requests to third‐party AI services to avoid abuse and unexpected costs.

Key security requirements for the project include:
- Authentication: Securely manage and validate API keys provided by users.
- Authorization: Implement access controls for paid features and sensitive endpoints.
- Input Validation: Proper check and sanitization of all user inputs, including URLs and file data.
- Cryptography: Use secure channels (HTTPS, TLS) for all communications with external services and enforce encryption for sensitive environment data.

---

# DESIGN

The system is architected as a multi-container application with a separate frontend and backend. The frontend (developed using React with Vite) provides the main user interface for uploading screenshots or video, setting API keys, and viewing generated code. The backend (using FastAPI) manages prompt assembly, communication with multiple third-party AI models, image generation, evaluation processing, and logging.

## C4 CONTEXT

The context diagram below illustrates the high-level interactions between the various entities in the system.

```mermaid
graph LR
    User[User (Browser)]
    Frontend[Frontend Application<br/>(React/Vite)]
    Backend[Backend Service<br/>(FastAPI)]
    OpenAI[OpenAI API]
    Anthropic[Anthropic API]
    Gemini[Gemini API]
    Replicate[Replicate API<br/>(Image Generation)]
    ScreenshotAPI[Screenshot Service<br/>(ScreenshotOne)]

    User -->|Interacts via Web UI| Frontend
    Frontend -->|REST/WebSocket API Calls| Backend
    Backend -->|Invokes| OpenAI
    Backend -->|Invokes| Anthropic
    Backend -->|Invokes| Gemini
    Backend -->|Invokes| Replicate
    Frontend -->|Optional: User triggers screenshot| ScreenshotAPI
```

Below is the table describing the elements of the context diagram:

| Name           | Type               | Description                                                     | Responsibilities                                                  | Security Controls                                  |
|----------------|--------------------|-----------------------------------------------------------------|-------------------------------------------------------------------|----------------------------------------------------|
| User           | External Actor     | End user interacting with the application via a browser         | Upload screenshots/video, configure API keys, review generated code | Client-side storage of settings; Use HTTPS         |
| Frontend       | Web Application    | React/Vite application that renders the UI                      | Provide an interactive interface; capture user input              | Validate user input; Secure handling of API keys   |
| Backend        | API Service        | FastAPI server handling prompt assembly and AI integration        | Process requests; aggregate AI responses; generate code            | CORS configuration; use environment variables      |
| OpenAI API     | Third-Party Service| Offers AI completions for code generation (GPT-4 models)           | Generate code based on text/image prompts                           | Secure HTTPS communication; rate limiting          |
| Anthropic API  | Third-Party Service| Provides alternative AI completions (Claude models)                | Generate code based on text/image prompts                           | Secure HTTPS communication; API key management      |
| Gemini API     | Third-Party Service| Provides AI completions (Gemini models)                            | Complement code generation                                              | Secure HTTPS communication; API key management      |
| Replicate API  | Third-Party Service| Provides image generation for replacing placeholder images         | Generate high-quality images using models like Flux Schnell         | Secure HTTPS communication; dependency on API key  |
| ScreenshotAPI  | Third-Party Service| External API to capture screenshots of web pages                   | Capture website screenshots when required                           | API key management; HTTPS communication            |

---

## C4 CONTAINER

The container diagram shows the high-level architecture and distribution of responsibilities between major containers.

```mermaid
graph LR
    subgraph Client Side
        FE[Frontend Container<br/>(React/Vite)]
        User[User Browser]
    end

    subgraph Server Side
        BE[Backend Container<br/>(FastAPI)]
        Eval[Eval & Testing Module]
    end

    subgraph External Services
        AI1[OpenAI API]
        AI2[Anthropic API]
        AI3[Gemini API]
        IMG[Replicate API<br/>(Image Generation)]
        SS[Screenshot Service]
    end

    User --> FE
    FE --> BE
    BE --> AI1
    BE --> AI2
    BE --> AI3
    BE --> IMG
    FE -- Optional screenshot --> SS
    BE --> Eval
```

The following table describes the container elements:

| Name        | Type             | Description                                                           | Responsibilities                                           | Security Controls                                             |
|-------------|------------------|-----------------------------------------------------------------------|------------------------------------------------------------|---------------------------------------------------------------|
| Frontend    | Web Container    | React-based client application built with Vite                        | Render UI; manage settings; communicate with backend        | Input validation; use HTTPS; secure handling of keys          |
| Backend     | API Container    | FastAPI application running Python code in a container (via Poetry)     | Process requests; manage prompt generation; interface with AI APIs; serve evaluations | CORS (currently open); environment variable management; logging |
| Eval Module | Internal Module  | Part of the backend dedicated to running evaluations and tests          | Run model evaluations; orchestrate batch processing           | Internal network protection; proper error signaling            |
| External AI | Third-Party APIs | External providers (OpenAI, Anthropic, Gemini) for code generation       | Perform AI completions for code and prompt responses           | Use secure channels (HTTPS); API key management                 |
| Image Gen   | External API     | Replicate API for generating images from placeholders                   | Convert placeholder URLs to generated images                  | Use secure channels and API key protection                      |
| Screenshot  | External Service | ScreenshotOne or similar service capturing live webpage screenshots      | Provide captured screenshots when required                    | API key management; secured access via HTTPS                    |

---

## DEPLOYMENT

The system is deployed as a multi-container solution orchestrated by Docker Compose. The backend container is built from a Python slim image using Poetry for dependency management, while the frontend is built using a Node container with Yarn. They communicate over a shared network, with ports mapped externally (default: Frontend on 5173 and Backend on 7001).

```mermaid
graph TD
    Host[Deployment Host]
    subgraph Docker Host
        FE_Docker[Frontend Container<br/>(Node/Vite)]
        BE_Docker[Backend Container<br/>(Python/FastAPI)]
    end
    Host -- HTTP/WS Ports --> FE_Docker
    Host -- HTTP Port --> BE_Docker
```

The table below describes the deployment elements:

| Name           | Type            | Description                                                  | Responsibilities                                          | Security Controls                                                |
|----------------|-----------------|--------------------------------------------------------------|-----------------------------------------------------------|------------------------------------------------------------------|
| Frontend Docker| Docker Container| Container built using Node 22 image running the React/Vite app| Serve the web UI; provide interactive front end            | Container isolation; non-root user; secure dependency versions   |
| Backend Docker | Docker Container| Container built on python:3.12-slim with Poetry for FastAPI   | Handle API requests; communicate with AI APIs; process evaluations | Container isolation; use of environment variables; minimal privileges |
| Docker Compose | Orchestration   | Docker Compose file coordinating multi-container deployment   | Define build contexts, environment variables, port mapping  | Use managed networks; secure Docker host configuration            |

---

## BUILD

The build process follows an automated pipeline incorporating code analysis, testing, and container image creation:
- Developers work locally using pre-commit hooks, automated testing (pytest, pyright), and linters.
- The backend is built using Poetry (dependencies defined in pyproject.toml) and packaged into a Docker image.
- The frontend uses Yarn for dependency management and Vite as the build tool to bundle assets.
- Docker Compose is used both for local development and for production deployment.
- Security controls in the build process include SAST scanning, dependency scan tools, and enforcement of coding best practices via pre-commit and CI testing.

The following diagram illustrates the build process:

```mermaid
flowchart TD
    A[Developer Code Commit]
    B[Local Linters & Pre-commit Hooks]
    C[Run Automated Tests (pytest, pyright)]
    D[Build Frontend Bundle (Yarn/Vite)]
    E[Build Backend Image (Poetry/Docker)]
    F[Docker Compose Orchestration]
    G[Deploy to Production Environment]

    A --> B
    B --> C
    C --> D
    C --> E
    D & E --> F
    F --> G
```

Key build security controls:
- Automatic linting and static code analysis.
- Enforced testing and code review before image build.
- Verification of external dependency security (via Poetry lock file and Yarn lock file).

---

# RISK ASSESSMENT

Critical business processes include the conversion of visual design inputs (screenshots, video) into high-fidelity code. The accuracy and quality of generated code directly affect user satisfaction and downstream development costs.

Data being protected:
- API keys for third-party services (OpenAI, Anthropic, Gemini, Replicate) are highly sensitive.
- User-supplied images and video data that may contain proprietary or sensitive design information.
- Generated code output which might include business logic or design elements proprietary to the customer.

Sensitivity:
- API keys must be protected from exposure; any leak could lead to unauthorized access and unexpected charges.
- Design assets may be confidential and should be transmitted over secure channels.
- The transformation process itself must validate inputs to prevent injection attacks.

---

# QUESTIONS & ASSUMPTIONS

Questions:
- Will the production deployment enforce a stricter CORS policy and secure API gateway?
- What are the scalability expectations regarding load for AI API calls and image generation?
- How frequently will API keys be rotated and what is the process for secure key management in production?
- Is there an audit/logging requirement for prompt interactions with third-party AI services?
- What is the fallback process if one of the AI services becomes unavailable or rate-limited?

Assumptions:
- The initial risk tolerance is moderate given the experimental nature of the open source project.
- Users (especially enterprise clients) will provide their own API keys and are expected to manage them securely.
- The hosted version will have additional layers of security (authentication, authorization, HTTPs) implemented beyond the current open development configuration.
- The Dockerized environment provides sufficient isolation and control for the production deployment.
- The development environment is trusted and all API interactions occur over secure channels (HTTPS).
