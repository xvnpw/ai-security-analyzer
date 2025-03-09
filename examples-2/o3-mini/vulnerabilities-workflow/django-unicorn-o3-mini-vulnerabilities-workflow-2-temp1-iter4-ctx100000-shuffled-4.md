- **Vulnerability Name:** Cross‑Site Scripting (XSS) via Unsafe “Safe” Component Property Rendering

  **Description:**
  Django Unicorn automatically escapes component property values before rendering them into the DOM. However, if a developer chooses to bypass this behavior—either by listing a property in the component’s `Meta.safe` tuple or by applying the Django “safe” filter in the template—the value is rendered without HTML‑escaping. An attacker who is able to control user input (for example, via an AJAX update bound by a `unicorn:model` directive) can supply a malicious payload containing JavaScript. When the component re‑renders, the unsanitized (raw) value gets injected directly into the HTML, thus executing the attacker’s script.
  **Step‑by‑step trigger:**
  1. A reactive component is defined that contains a public property (for example, a text field).
  2. The property is deliberately marked as “safe” by including its name in the component’s `Meta.safe` tuple or by using the Django “safe” template filter in its template.
  3. The component is rendered and bound via AJAX so that user input updates the property.
  4. An attacker submits a crafted payload—for example, `<script>alert('XSS');</script>`—through the reactive input interface.
  5. Because the property is marked safe, the framework bypasses its standard sanitization (which is normally performed via functions such as `sanitize_html()`).
  6. The raw HTML/JavaScript payload is injected into the page’s DOM and immediately executed in the victim’s browser.

  **Impact:**
  An attacker can execute arbitrary JavaScript in the context of the victim’s browser session. This may lead to high‑impact consequences such as stealing session cookies, hijacking user sessions, or manipulating sensitive data. Since reactive components can be embedded widely across a Django Unicorn–powered application, the risk is amplified once a property is marked safe.

  **Vulnerability Rank:** High

  **Currently Implemented Mitigations:**
  - By default, Django Unicorn serializes component data and passes values through a sanitizer (via the `sanitize_html()` helper in `django_unicorn/utils.py`) that HTML‑encodes values before sending them to the browser.
  - Properties are not marked as “safe” unless the developer explicitly opts in via the `Meta.safe` tuple or applies the Django “safe” filter.
  - Developer documentation clearly warns that marking properties as safe bypasses automatic escaping and inherently exposes the component to XSS risk.

  **Missing Mitigations:**
  - There is no runtime check or additional server‑side sanitization for properties that are deliberately marked safe. Once a property is opted in as safe, any data submitted by the client is rendered without further HTML‑encoding.
  - No automatic mechanism exists to validate that user‑supplied input for safe properties is properly sanitized even if it is marked safe.

  **Preconditions:**
  - The component must contain at least one property that is declared in its `Meta.safe` tuple or is rendered with the Django “safe” filter—thus bypassing normal HTML‑escaping.
  - An attacker must be able to control the input that gets bound (for example, via an AJAX call using `unicorn:model`).
  - There is no additional server‑side sanitization specifically for user‑supplied data that is rendered via the safe property.

  **Source Code Analysis:**
  - In the Unicorn component’s update flow (for example, within the method that collects frontend context variables in `django_unicorn/views/utils.py`), properties are normally passed through a sanitization function (like `sanitize_html()`) that ensures HTML‑special characters (such as `<` and `>`) are encoded.
  - However, in the final rendering logic (in files such as `django_unicorn/views/__init__.py`), the framework checks for any safe fields defined by the developer (by inspecting `component.Meta.safe`). If a property is found in this list, its current value is wrapped with Django’s `mark_safe()` function without further inspection or escaping.
  - This logic directly re‑injects the raw property value into the DOM. If an attacker has been able to supply a payload like `<script>alert('XSS');</script>`, that value will be rendered unencoded and execute in the browser context.
  - Additional tests (for example, those in `tests/views/message/test_sync_input.py` and similar setter tests) show that nested properties and direct property updates do not enforce any secondary sanitization when the safe marker is present.

  **Security Test Case:**
  **Objective:** Prove that an attacker-controlled value submitted to a component property marked as safe is rendered without HTML‑escaping and that the script executes.
  **Test Steps:**
  1. **Prepare a Component with a Safe Property:**
     - Create a test component (for example, `SafeExampleView`) that declares a public property (e.g. `something_safe`) and explicitly lists it in its `Meta.safe` tuple.
     - *Example:*
       ```python
       class SafeExampleView(UnicornView):
           something_safe = ""

           class Meta:
               safe = ("something_safe",)
       ```
  2. **Embed the Component in a Template:**
     - In the component’s template, output the property without applying any additional filters (i.e. using `{{ something_safe }}`), knowing that it will not be auto-escaped because it is safe.
  3. **Simulate an AJAX Update:**
     - From an external test client, simulate an AJAX request (or use the provided test helpers) that updates the property bound via `unicorn:model` with the malicious payload `<script>alert('XSS');</script>`.
  4. **Submit the Request:**
     - Ensure that the request is properly authenticated (with CSRF protection, etc.) and that the payload is accepted by the component’s update endpoint.
  5. **Inspect the Response:**
     - Examine the HTML output in the response. Verify that the rendered HTML contains the raw `<script>` tags without Unicode or HTML entity escaping.
  6. **Browser Verification (Optional):**
     - Load the updated component in a browser environment and verify that the injected script executes (for example, by triggering an alert or by observing any DOM manipulation).
  7. **Cleanup:**
     - Revert any test changes and confirm that components not marked as safe are still rendered with proper escaping.
