# Vulnerability List

## Vulnerability 1: Arbitrary API Key Injection via WebSocket Parameters
**Vulnerability Name**: API Key Injection via Unvalidated User Input
**Description**:
The `extract_params` function in `routes/generate_code.py` allows clients to specify API keys (`openAiApiKey` and `anthropicApiKey`) through request parameters. These keys are directly used in LLM API calls without validation. An attacker can:
1. Craft a request with arbitrary API keys (e.g., `POST` to `/generate-code` with malicious keys).
2. Use the backend to perform actions using those keys (e.g., generating code via OpenAI/Anthropic), leading to:
   - Unauthorized API usage (billing fraud).
   - Exposure of sensitive data/model outputs via the attacker's keys.
**Impact**: High
An attacker could misuse legitimate API keys for malicious purposes (e.g., spamming models, generating harmful content), costing the key owner financially or exposing their account data.
**Vulnerability Rank**: High
**Currently Implemented Mitigations**: None. User input is directly used for API keys.
**Missing Mitigations**:
- API keys should be stored in the backend's secure environment and not accepted from client requests.
- Validate and restrict key usage to only the backend's own credentials.
**Preconditions**: The attacker can send arbitrary requests to the `/generate-code` WebSocket endpoint.
**Source Code Analysis**:
- In `routes/generate_code.py`, `extract_params` reads keys from client parameters:
  ```python
  openai_api_key = get_from_settings_dialog_or_env(params, "openAiApiKey", OPENAI_API_KEY)
  anthropic_api_key = get_from_settings_dialog_or_env(params, "anthropicApiKey", ANTHROPIC_API_KEY)
  ```
  The `get_from_settings_dialog_or_env` function prioritizes user-provided values over environment variables.
- These keys are later used in LLM calls (e.g., `stream_openai_response`).
**Security Test Case**:
1. Send a WebSocket request to `/generate-code` with parameters:
   ```json
   {
     "generatedCodeConfig": "html_tailwind",
     "inputMode": "image",
     "openAiApiKey": "ATTACKER_API_KEY",
     "anthropicApiKey": "ATTACKER_ANTHROPIC_KEY"
   }
   ```
2. Observe backend using the attacker's keys, generating content via their APIs.
3. Validate API logs show unauthorized usage of the attacker's keys.

---

## Vulnerability 2: Exposure of Environment Variables in Docker Configuration
**Vulnerability Name**: Sensitive Data Exposure via Dockerfile
**Description**:
The backend's Dockerfile copies the entire project directory (`COPY ./ ./`) into the container. If the `.env` file (containing API keys/secrets) is present in the build context, it will be exposed in the container. Attackers with access to the container’s filesystem (e.g., via container escape) can read sensitive credentials.
**Impact**: High
Compromise of API keys, leading to unauthorized access to cloud services/models.
**Vulnerability Rank**: High
**Currently Implemented Mitigations**: None. The Dockerfile does not exclude `.env`.
**Missing Mitigations**:
- Exclude `.env` in Dockerfile (`COPY . /app/` and use `.dockerignore`).
- Use environment variables in Docker Compose instead of storing them in `.env` within the project.
**Preconditions**: The `.env` file is present in the project directory during Docker build.
**Source Code Analysis**:
- Dockerfile snippet:
  ```dockerfile
  COPY ./ /app/
  ```
  This copies all files, including `.env`.
**Security Test Case**:
1. Add a `.env` file with `TEST_SECRET=secret_value` to the backend directory.
2. Build the Docker image and run it.
3. Execute `docker run -it <image> cat /app/.env` to retrieve the secret.

---

## Vulnerability 3: Unvalidated OpenAI Base URL Configuration
**Vulnerability Name**: Unvalidated OpenAI Base URL Leading to MITM
**Description**:
The `OPENAI_BASE_URL` environment variable is used in `routes/generate_code.py` without validation. If an attacker can manipulate this variable (e.g., via insecure deployment), they can redirect API traffic to a malicious endpoint, intercepting sensitive data (API keys, generated code).
**Impact**: High
Attackers could steal API keys or tamper with model responses.
**Vulnerability Rank**: High
**Currently Implemented Mitigations**: None. The base URL is used as-is.
**Missing Mitigations**:
- Validate that `OPENAI_BASE_URL` points to a trusted domain (e.g., `api.openai.com`).
- Use HTTPS and certificate pinning.
**Preconditions**: The attacker can set `OPENAI_BASE_URL` in the environment (e.g., via misconfigured deployment).
**Source Code Analysis**:
- `config.py` reads `OPENAI_BASE_URL` from environment variables.
- Used directly in `stream_openai_response`:
  ```python
  client = AsyncOpenAI(api_key=api_key, base_url=base_url)
  ```
**Security Test Case**:
1. Set `OPENAI_BASE_URL=http://attacker-controlled.com`.
2. Trigger an API call via `/generate-code`.
3. Monitor MITM proxy to capture requests/responses.
