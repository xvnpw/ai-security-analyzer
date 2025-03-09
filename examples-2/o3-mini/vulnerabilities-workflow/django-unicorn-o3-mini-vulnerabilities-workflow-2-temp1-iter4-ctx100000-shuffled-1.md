- **Vulnerability Name:** Cross‑Site Scripting (XSS) via Unsafe Opt‑In (Meta.safe) in Component Field Rendering

  - **Description:**
    - A developer may choose to display rich HTML content by opting out of the default autoescaping. This is done by including one or more component field names in the component’s `Meta.safe` configuration.
    - **Step‑by‑Step Trigger:**
      1. **Component Configuration:** A Unicorn component is created (or modified) so that at least one field (for example, `dangerous_content`) is flagged safe via:
         ```python
         class Meta:
             safe = ("dangerous_content",)
         ```
      2. **Malicious Input Delivery:** An attacker (or an untrusted user) supplies a payload such as
         `<script>alert('XSS');</script>`
         into that field via an AJAX call or a form submission.
      3. **Bypassing Escaping:** Because the field is marked safe, the framework’s default autoescaping is bypassed. Inspection of the serialization process in files like `django_unicorn/serializer.py` shows that methods such as `_get_model_dict` and `_json_serializer` directly pass through the field’s content without invoking additional sanitization.
      4. **Dynamic Rendering:** In the update cycle (including in property update functions as seen in `django_unicorn/views/action_parsers/utils.py`), the unsanitized value is merged into the component’s frontend context and later re‑rendered on the client’s browser.
      5. **Script Execution:** The browser inserts the raw HTML into the DOM. As a result, the malicious `<script>` element is executed, leading to an XSS attack.

  - **Impact:**
    - An attacker who successfully exploits this flaw can execute arbitrary JavaScript in the context of a victim’s browser.
    - This may allow the attacker to hijack sessions, steal credentials, perform client‑side manipulations, or modify the page’s content.

  - **Vulnerability Rank:** High

  - **Currently Implemented Mitigations:**
    - **Default Auto‑escaping:** By design, Unicorn auto‑escapes field output so that HTML characters are rendered inert.
    - **Explicit Safe Opt‑In:** The framework requires an intentional developer action (using `Meta.safe`) to disable autoescaping for a field.
    - **Sanitization during Serialization:** In functions like `_get_model_dict` and `_json_serializer` (in `django_unicorn/serializer.py`), data is normally processed through Django’s JSON encoder unless the safe opt‑in mechanism is activated.

  - **Missing Mitigations:**
    - **Runtime Warning or Audit:** There is no built‑in warning or logging to alert developers upon marking a field as safe.
    - **Additional or Configurable Re‑Sanitization:** Once a field is designated safe, no secondary sanitation is applied before the data is injected into the DOM.
    - **Enhanced Input Validation:** The framework does not enforce stricter input validation on fields opted out of autoescaping, which means that attacker‑controlled input can bypass normal sanitization defenses.

  - **Preconditions:**
    - The component’s Meta configuration must explicitly list one or more fields in its `safe` tuple.
    - An attacker (or an untrusted source) must be able to control the value sent to that field (via AJAX, form submission, or similar).
    - The component’s template must render the field’s value using a standard template tag (e.g. `{{ dangerous_content }}`) without applying additional filters.

  - **Source Code Analysis:**
    - In `django_unicorn/serializer.py`:
      - The `_get_model_dict` function serializes Django models by extracting field data. When a field is marked safe (via developer configuration), its value is inserted into the JSON payload without further escaping.
      - The `_json_serializer` method processes Unicorn component instances and passes attribute values “as‑is” if the developer has chosen to disable auto‑escaping.
    - In `django_unicorn/views/action_parsers/utils.py`:
      - The function `set_property_value()` accepts payloads to update component properties. When the property corresponds to a field that has been flagged safe, the value is set directly on the component without running additional sanitization routines.
    - The combination of these behaviors means that if malicious HTML/JS is supplied (and the field is opted in as safe), this content is later rendered directly into the DOM, thereby facilitating an XSS attack.

  - **Security Test Case:**
    1. **Setup:**
       - Create a test component (e.g. `TestXSSComponent`) with a field called `dangerous_content` and configure its `Meta` as follows:
         ```python
         class TestXSSComponent(UnicornView):
             dangerous_content = "default content"

             class Meta:
                 safe = ("dangerous_content",)
         ```
    2. **Template:**
       - Create a corresponding template (e.g. `test_xss_component.html`) that renders the field without any additional escaping:
         ```html
         <div>
           {{ dangerous_content }}
         </div>
         ```
    3. **Attack:**
       - Use an HTTP testing client or a browser’s developer console to issue an AJAX POST request to update the component. In the JSON payload, set:
         ```json
         {
           "dangerous_content": "<script>alert('XSS');</script>"
         }
         ```
         (Ensure that the proper checksum is calculated so that the request is accepted.)
    4. **Verification:**
       - Examine the JSON response and the resultant re‑rendered HTML. Confirm that the HTML output contains the unescaped `<script>alert('XSS');</script>` block.
       - Use a headless browser or security proxy to verify that the injected script actually executes (for instance, by observing an alert pop‑up), thereby establishing that the XSS is exploitable.
