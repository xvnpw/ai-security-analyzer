## Vulnerability List:

### Cross-Site Scripting (XSS) via Partial Updates

- Description:
    1. An attacker crafts a malicious string containing JavaScript code.
    2. The attacker inputs this malicious string into a form field that is bound to a Django Unicorn component using `unicorn:model`.
    3. The component is configured to use `unicorn:partial` to update a specific part of the DOM when an action is triggered.
    4. The attacker triggers an action that causes a partial update, and the malicious string is rendered into the targeted DOM element without proper sanitization.
    5. The victim's browser executes the attacker's JavaScript code, leading to XSS.

- Impact:
    - Critical: Successful XSS can lead to account takeover, session hijacking, sensitive data theft, redirection to malicious sites, and defacement of the application.

- Vulnerability Rank: critical

- Currently implemented mitigations:
    - Django Unicorn might be using Django's template auto-escaping by default, which could mitigate some XSS risks. However, the documentation explicitly mentions `Meta.safe` and `safe` template filter to disable HTML encoding, which implies that by default, encoding is enabled to prevent XSS. It is not clear if partial updates are also correctly escaped in all scenarios, especially when developers might use `safe` filter or `Meta.safe` incorrectly.

- Missing mitigations:
    - Explicit and robust sanitization of all user-provided content rendered through partial updates on the server-side, regardless of template auto-escaping.
    - Security documentation strongly advising against using `Meta.safe` and `safe` template filter unless strictly necessary and with extreme caution.
    - Security tests specifically covering XSS in partial updates with various scenarios, including different HTML tags and JavaScript events.

- Preconditions:
    - A Django Unicorn component is implemented with `unicorn:partial` attribute to update a part of the DOM.
    - User input is rendered in the targeted DOM element during a partial update.
    - The rendered content is not properly sanitized on the server-side before being sent to the client.

- Source code analysis:
    - Based on the provided documentation, there is no source code to analyze directly. However, the vulnerability is hypothesized based on the feature description of partial updates and general web security principles. To confirm this vulnerability, the code responsible for rendering partial updates needs to be analyzed. Specifically, the code path that handles server-side rendering of the component after an action and before sending the partial DOM update to the client must be examined to ensure proper sanitization. It needs to be verified if Django's auto-escaping is consistently applied and if there are any scenarios where developer configurations (like `Meta.safe` or `safe` filter) could bypass sanitization leading to XSS.

- Security test case:
    1. Create a Django Unicorn component with a text input field bound with `unicorn:model` and an element with `unicorn:partial` that displays the input field's value.
    2. In the component's view, do not perform any explicit sanitization on the input value before rendering it in the partial template.
    3. In the component's template, use `unicorn:partial` to target an element to display the input value.
    4. As an attacker, input a malicious string into the text input, such as `<img src=x onerror=alert('XSS')>`.
    5. Trigger an action (e.g., blur event or button click) that causes a partial update of the targeted element.
    6. Observe if the JavaScript code `alert('XSS')` is executed in the browser, indicating a successful XSS vulnerability.
    7. Verify that the vulnerability can be triggered by different XSS payloads, including those using script tags and event handlers.
