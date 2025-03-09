- **Vulnerability Name:** Unescaped Output via Misuse of the Meta.safe Attribute
  **Description:**
  • A developer may add one or more property names to the component’s Meta.safe tuple to have those values rendered “as is” (using Django’s mark_safe) rather than undergoing the usual automatic HTML escaping.
  • If that property is later updated via user input (for example, through an AJAX call that patches the property’s value), an attacker can supply malicious HTML or script code (for example, `<script>alert('XSS');</script>`) that will be stored in the property.
  • When the component re‑renders, the unsafe value is injected directly into the page’s DOM.
  **Impact:**
  • Malicious script execution (XSS) in the browser that can lead to session hijacking, drive‑by downloads, data theft, or site defacement.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  • By default, the framework automatically HTML‑escapes all component property values, so data provided by end‑users is not rendered as raw HTML.
  • The “safe” mechanism is opt‑in only—if a property is not explicitly marked as safe it will be auto‑escaped.
  **Missing Mitigations:**
  • No independent sanitization is performed on properties flagged as safe; once a developer opts out of escaping, it is up to that developer to validate or sanitize any user‑supplied data.
  • There are no built‑in warnings or static analysis checks that alert a developer when a property containing dynamic, user‑controlled data is marked safe.
  **Preconditions:**
  • The component’s developer adds a property name to bypass default auto‑escaping (via Meta.safe).
  • This safe property is updated with data (for example, over an AJAX call) that an attacker controls.
  **Source Code Analysis:**
  • In the component rendering lifecycle, during preparation of the “frontend context” (e.g. before serializing properties with serializer.dumps), the code iterates over the list of safe‑marked fields and applies Django’s mark_safe.
  • This bypasses the normal Django template auto‑escaping so that any string—even one containing malicious HTML—is embedded directly in the JSON payload and ultimately merged into the DOM via AJAX updates.
  **Security Test Case:**
  1. Create a simple component (e.g. a HelloWorldView) that defines a property (such as “message”) and includes it in its rendered template using `{{ message }}`.
  2. In the component’s Meta class, list “message” in the safe tuple.
  3. Submit an AJAX request (using the Unicorn message endpoint) to update the “message” property with an attack string such as `<script>alert('XSS');</script>`.
  4. Confirm via the JSON payload that the dangerous content is embedded without escaping.
  5. In a browser, trigger the update and observe that the alert is executed—this confirms that bypassing auto‑escaping can lead to an XSS attack.

- **Vulnerability Name:** Insecure Output via Use of the “safe” Template Filter on Component Variables
  **Description:**
  • Even if a component does not use Meta.safe to designate a property as safe, a template designer may apply Django’s “safe” filter directly (for example, writing `{{ message|safe }}` in the component template).
  • When this filter is used on a property holding untrusted, user‑supplied data, the value bypasses auto‑escaping.
  • An attacker who can control (or inject via AJAX) the value of such a property may supply a payload like `<script>malicious()</script>`, causing it to be rendered directly in the DOM.
  **Impact:**
  • Arbitrary script execution (XSS), which may allow session hijacking, data theft, drive‑by downloads, or site defacement.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  • Django templates auto‑escape variable output by default. The safe filter is applied only when a developer explicitly adds it.
  **Missing Mitigations:**
  • The framework does not provide additional sanitization for data that has been marked safe via the safe filter, meaning it relies entirely on the developer’s discipline.
  **Preconditions:**
  • The component’s template explicitly applies the “safe” filter (or another mechanism that disables auto‑escaping) to one or more variables that later receive user‑controlled input.
  **Source Code Analysis:**
  • Documentation and sample templates in the repository show that a developer can bypass escaping by using the safe filter.
  • Even though the backend logic (including JSON serialization) works correctly, once escaping is bypassed in the template, the raw, unsanitized value is sent to the client and inserted into the DOM.
  **Security Test Case:**
  1. Create a component whose template uses the safe filter to render a variable (for instance, `<div>{{ message|safe }}</div>`).
  2. Using an AJAX call (or the Unicorn message endpoint), update the “message” property with a payload such as `<script>alert('XSS')</script>`.
  3. Verify that the JSON response from the view does not escape the dangerous payload.
  4. In a browser, trigger the update and observe that the injected script executes—demonstrating the vulnerability.

- **Vulnerability Name:** Unsanitized Nested Property Update Allowing XSS
  **Description:**
  • The framework supports updating nested properties via dot‑notation (for example, updating “nested.field” on a component).
  • When processing an AJAX call, the function responsible for setting property values (in `set_property_value` in the action parsers) splits the property name by “.” and iterates over nested attributes to apply the update.
  • If a developer opts out of auto‑escaping (either by including a nested property in Meta.safe or by applying the safe filter in the template) and the property is updated with user‑supplied data, the update is applied without additional sanitization.
  • As a result, an attacker can inject malicious payloads (for example, `<script>alert('XSS');</script>`) into a nested property that is later rendered unescaped into the DOM.
  **Impact:**
  • The injection of unsanitized HTML into nested output can lead to arbitrary JavaScript execution. This, in turn, puts users at risk of session hijacking, data leakage, and other XSS‐related attacks.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  • The framework’s default behavior is to auto‑escape all output; however, this protection is bypassed when a property (including nested ones) is explicitly marked as safe.
  **Missing Mitigations:**
  • There is no additional sanitization or validation for nested property values updated via dot‑notation if the property is marked as safe.
  • The system does not warn or enforce static checks to detect if nested properties (which might contain sub‑objects) are being flagged safe while still receiving untrusted input.
  **Preconditions:**
  • A developer opts‑out of the default auto‑escaping for a nested property (for example, by adding “nested.field” to the Meta.safe tuple or by using the safe filter in the template).
  • An attacker is able to supply malicious input that targets the nested property via an AJAX update.
  **Source Code Analysis:**
  • In `set_property_value` (located in `django_unicorn/views/action_parsers/utils.py`), the property name is split on “.” so that nested properties are updated one level at a time.
  • As the function traverses the nested structure, it directly applies the value using either a call to a helper (if available) or Python’s `setattr` without performing any extra sanitization step.
  • This means that if the nested property is considered “safe” from a template perspective, then any injected payload will be rendered verbatim.
  **Security Test Case:**
  1. Create a component that defines a nested property (for example, a Unicorn field “property_one.nested_property_one”).
  2. In the component’s Meta class, mark the nested property (e.g. “property_one.nested_property_one”) as safe so it will not be auto‑escaped by default.
  3. Use an AJAX call (or the Unicorn message endpoint) to update the nested property with a payload such as `<script>alert('XSS');</script>`.
  4. Render the component and capture the resulting HTML.
  5. Verify that the JSON payload (and the subsequently rendered DOM) contains the unsanitized malicious payload and that the injected script executes in the browser.
