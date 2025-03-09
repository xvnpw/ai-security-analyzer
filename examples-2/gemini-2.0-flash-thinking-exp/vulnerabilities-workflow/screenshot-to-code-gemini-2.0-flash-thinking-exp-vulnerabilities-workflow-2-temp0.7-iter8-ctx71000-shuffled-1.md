- Vulnerability Name: Insecure Storage of API Keys in Frontend
- Description: The application may store OpenAI and Anthropic API keys in the frontend (e.g., browser's local storage) without encryption. An attacker with local access to the user's machine could potentially retrieve these keys and misuse them.
- Impact: If an attacker gains access to the API keys, they can make requests to the OpenAI or Anthropic APIs using the victim's credentials. This could lead to unauthorized usage of the victim's API quota and potentially incur costs for the victim.
- Vulnerability Rank: Medium
- Currently Implemented Mitigations: There are no explicit mitigations for secure storage of API keys mentioned in the provided files. The documentation states that keys are "only stored in your browser. Never stored on our servers.", which implies local storage but not necessarily secure storage.  No changes observed in provided backend files to indicate any mitigation.
- Missing Mitigations: Implement encryption for storing API keys in the frontend. If API keys are stored in browser storage, they should be encrypted using a robust encryption mechanism to prevent unauthorized access from local machine access.
- Preconditions:
    - User runs the screenshot-to-code application locally.
    - User configures OpenAI API key or Anthropic API key via the frontend settings.
    - An attacker gains local access to the user's machine, for example, through malware, physical access, or if multiple users share the same machine.
- Source Code Analysis:
    - **Frontend code analysis is still required to confirm this vulnerability.** The provided backend files (`imported_code_prompts.py`, `evals/runner.py`, `prompts/types.py`, `image_processing/utils.py`, `pyproject.toml`, `routes/screenshot.py`, `fs_logging/core.py`, `routes/evals.py`, `prompts/claude_prompts.py`, `Dockerfile`) do not contain information about how API keys are handled or stored in the frontend.
    - To confirm, analyze frontend Javascript code (not provided yet) for usage of `localStorage`, `sessionStorage`, cookies, or any other client-side storage mechanisms when handling API keys from user settings.
    - If API keys are stored in plain text in any of these storage locations, the vulnerability exists.
    - Backend code does not directly manage the storage of OpenAI/Anthropic API keys in the user's browser, so backend analysis is not relevant for this specific vulnerability.
- Security Test Case:
    1. Set up the screenshot-to-code application locally as described in the `README.md`.
    2. Open the application in a web browser and navigate to the settings dialog (mentioned by "gear icon" in `README.md` and `Troubleshooting.md`).
    3. Enter a valid OpenAI API key (you can use a test key if available or a real key for testing purposes, but be cautious).
    4. Close the settings dialog.
    5. Open browser's developer tools (usually by pressing F12).
    6. Navigate to the "Application" or "Storage" tab in the developer tools.
    7. Inspect `Local Storage` or `Session Storage` for the application's domain (usually `localhost:5173` if running locally).
    8. Look for any keys that might store the API key (e.g., keys with names like `openAiApiKey`, `settings`, `config`, etc.).
    9. If you find a key that appears to store the API key, examine its value.
    10. If the API key is stored in plain text (i.e., you can directly read the API key string), then the vulnerability exists.
