### Vulnerability: Cross-Site Scripting (XSS) via Partial Updates

* Vulnerability Name: XSS via Partial Updates
* Description:
    1. An attacker crafts a malicious payload for a component interaction that is designed to trigger a partial update.
    2. The attacker manipulates the `unicorn:partial` target in the client-side request to point to a broader DOM element than intended by the component logic, or to a newly crafted element within the component.
    3. The server-side component processes the action and generates a response containing a partial update targeted at the attacker-manipulated element.
    4. The response includes a crafted HTML payload, potentially containing malicious JavaScript, which is intended to be injected into the targeted DOM element via `morphdom` during the partial update process.
    5. Because the scope of the update is broader than expected or targeted a crafted element, the malicious JavaScript is injected into the DOM and executed in the user's browser, leading to XSS.

* Impact:
    Successful exploitation of this vulnerability allows an external attacker to execute arbitrary JavaScript code in the context of the victim's browser. This can lead to:
    - Account Takeover: Stealing session cookies or credentials to impersonate the user.
    - Data Theft: Accessing sensitive information displayed on the page or transmitted by the user.
    - Website Defacement: Modifying the content of the web page to mislead or harm users.
    - Redirection to Malicious Sites: Redirecting users to attacker-controlled websites for phishing or malware distribution.
    - Further Attacks: Using the compromised context to launch further attacks against the user or the application.
* Vulnerability Rank: high
* Currently implemented mitigations:
    - Django-unicorn uses `morphdom` library for DOM diffing and merging, which is designed to be secure.
    - Django templates auto-escape HTML content by default, which helps prevent basic XSS.
    - The documentation for `Meta.safe` mentions that fields are HTML encoded by default to prevent XSS attacks, and developers need to explicitly opt-in to disable encoding using `Meta.safe`.
    - The code includes tests for HTML encoding and `Meta.safe` functionality, indicating awareness of XSS risks.
* Missing mitigations:
    - Lack of server-side validation or sanitization of `unicorn:partial` targets to ensure they are within the expected component structure and prevent manipulation to broader scopes or crafted elements.
    - No explicit checks or sanitization of the HTML content being returned in partial updates to strictly prevent injection of `<script>` tags or other XSS vectors, assuming `morphdom` is solely responsible for security.
* Preconditions:
    - The application must use Django-unicorn's partial updates feature (`unicorn:partial`).
    - The application must not have implemented additional server-side validation of `unicorn:partial` targets or sanitization of partial update content.
    - The attacker needs to identify a component interaction that uses partial updates and allows manipulation of the request parameters (specifically the `unicorn:partial` target).
* Source code analysis:
    1. **`django_unicorn/views/__init__.py` - `_process_component_request` function:** This function handles the server-side logic for processing component requests, including partial updates.
    2. **Partial updates handling:** Inside `_process_component_request`, after rendering the component, the code checks for `partials` in the `action` payload.
    3. **Target element selection:** For each `partial`, it tries to find the target DOM element in the rendered component's HTML using `BeautifulSoup`. It searches for elements with `unicorn:key`, `id`, or just `id` based on `unicorn:partial` modifiers (`key`, `id` or none).
    ```python
    if partials and all(partials):
        soup = BeautifulSoup(rendered_component, features="html.parser")

        for partial in partials:
            partial_found = False
            only_id = False
            only_key = False

            target = partial.get("target")

            if not target:
                target = partial.get("key")

                if target:
                    only_key = True

            if not target:
                target.get("id")

                if target:
                    only_id = True

            if not target:
                raise AssertionError("Partial target is required")

            if not only_id:
                for element in soup.find_all():
                    if "unicorn:key" in element.attrs and element.attrs["unicorn:key"] == target:
                        partial_doms.append({"key": target, "dom": str(element)})
                        partial_found = True
                        break

            if not partial_found and not only_key:
                for element in soup.find_all():
                    if "id" in element.attrs and element.attrs["id"] == target:
                        partial_doms.append({"id": target, "dom": str(element)})
                        partial_found = True
                        break
    ```
    4. **DOM merging:** If a target is found, the `dom` (HTML string of the element) is added to `partial_doms`. This `partial_doms` list is then returned in the JSON response. The client-side JavaScript uses `morphdom` to merge these partial DOM updates into the existing DOM.
    5. **Vulnerability point:** The server-side code relies on client-provided `target`, `key`, and `id` to locate the DOM element for partial updates. There is no server-side validation to ensure that the target is legitimate and within the expected component structure. An attacker could potentially manipulate these targets to inject arbitrary HTML beyond the intended scope.
    6. **`django_unicorn/static/unicorn/js/unicorn.js` - JavaScript-side handling:** The JavaScript code sends the `unicorn:partial` target to the server and processes the `partials` from the response, using `morphdom` to update the DOM. If the server returns a malicious payload for a manipulated target, `morphdom` will apply the changes, potentially leading to XSS.

* Security test case:
    1. **Setup:** Create a Django-unicorn component that uses partial updates. For example, a simple component with a button that triggers a partial update to a `<span>` element.

    ```python
    # components/partial_xss.py
    from django_unicorn.components import UnicornView

    class PartialXssView(UnicornView):
        message = "Initial message"

        def update_message(self):
            self.message = "Updated message"
    ```

    ```html
    <!-- unicorn/partial_xss.html -->
    <div>
        <span id="target-element" unicorn:key="targetKey">{{ message }}</span>
        <button unicorn:click="update_message" unicorn:partial.key="targetKey">Update Message</button>
    </div>
    ```

    2. **Identify Request:** Inspect the network requests when clicking the "Update Message" button. Identify the AJAX POST request sent to the Django-unicorn endpoint. Note the component name and ID in the request payload.

    3. **Craft Malicious Payload:** Modify the request payload to inject a malicious JavaScript payload within the partial update. Specifically, manipulate the `actionQueue` to trigger the same action (`update_message`) but also craft a malicious `partials` array.

    Example modified request payload:
    ```json
    {
        "actionQueue": [
            {
                "payload": {
                    "name": "update_message"
                },
                "type": "callMethod",
                "partials": [
                    {
                        "key": "targetKey",
                        "target": "target-element-xss",
                        "id": null,
                        "dom": "<span unicorn:key=\"targetKey\" id=\"target-element-xss\"><script>alert('XSS Vulnerability!')</script></span>"
                    }
                ]
            }
        ],
        "data": {
            "message": "Initial message"
        },
        "checksum": "...",
        "id": "...",
        "epoch": 1678886400,
        "hash": "..."
    }
    ```
    Note: The `partials` array is manually crafted to include a `<span>` element with a `<script>` tag and an `alert('XSS Vulnerability!')`. The `target` is set to `target-element-xss` which may or may not actually exist in the original template.

    4. **Execute Test:** Send the modified AJAX request to the server using a tool like `curl`, `Postman`, or browser developer tools (Edit and Resend).

    5. **Verify XSS:** Check if the JavaScript code (`alert('XSS Vulnerability!')`) is executed in the browser when the response is processed. If an alert box appears, or if you can observe the JavaScript code being executed (e.g., using browser's debugger), then the XSS vulnerability via partial updates is confirmed.

    6. **Expected Result:** The JavaScript alert box should appear, demonstrating that arbitrary JavaScript code injected through the partial update was executed, confirming the XSS vulnerability.
