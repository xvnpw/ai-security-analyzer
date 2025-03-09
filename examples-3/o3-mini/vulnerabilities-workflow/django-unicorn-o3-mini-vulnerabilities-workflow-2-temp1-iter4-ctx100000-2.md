## Vulnerability List

### 1. Cross‑Site Scripting (XSS) via Unsanitized Component Output

**Description:**
- **Overview:**
  Django‑Unicorn is designed to escape user‑supplied data during AJAX–driven reactive updates. However, when a component’s property is explicitly configured as “safe” (for example, via its Meta safe tuple or by using Django’s “|safe” filter), the normal sanitization is bypassed.
- **Triggering the Vulnerability:**
  1. A developer creates a Unicorn component that renders a user‑supplied attribute. To display rich HTML, the developer configures this attribute as safe (e.g. via the component’s Meta safe declaration as demonstrated in the FakeComponentSafe definition).
  2. An attacker submits a payload such as:
     `<script>alert('XSS triggered');</script>`
     via a reactive input (using an AJAX request to the `/message/` endpoint) bound to that property.
  3. The AJAX request is processed by the Unicorn view. When the serializer (using orjson and the custom dumps method) encounters the safe property, it bypasses the typical call to the helper function (e.g. `sanitize_html`) that would ordinarily escape HTML characters.
  4. The response is merged into the DOM without further escaping.
  5. The injected payload is interpreted by the browser and executes the attacker‑supplied JavaScript.
- **Additional Details from the PROJECT FILES:**
  - The test “test_safe_html_entities_not_encoded” (in `tests/views/test_process_component_request.py`) confirms that when using a safe configuration, HTML (such as `<b>test1</b>`) is rendered verbatim in the component’s output.
  - The reactive endpoint handling (seen across message–processing tests) shows that input submitted via “syncInput” or “callMethod” actions is serialized without additional sanitization for properties designated as safe.

**Impact:**
- **User Impersonation & Session Hijacking:**
  Execution of malicious JavaScript can lead to theft of cookies and session data.
- **Malicious Redirects & DOM Modification:**
  An attacker can force redirections or modify the visual content of the page.
- **Arbitrary Code Execution:**
  Any script running in the page context, including access to sensitive data, can be executed.

**Vulnerability Rank:** High
*(Because if exploited, the unsanitized output in reactive updates could compromise all users who interact with the affected component.)*

**Currently Implemented Mitigations:**
- **Default Escaping:**
  In the standard execution flow, component properties are passed through helper functions (such as `sanitize_html` in `django_unicorn/utils.py`) which use Django’s built‑in HTML escaping.
- **Opt‑in Safe Output:**
  The framework does not mark properties as safe unless the developer explicitly opts in (e.g. via Meta.safe or the template filter “|safe”).
- **CSRF Protection:**
  AJAX endpoints used by Django‑Unicorn enforce CSRF validation.
- **HTML Processing:**
  When rendering components (for example, in `UnicornTemplateResponse.render`), the output is parsed (using BeautifulSoup) and reassembled, ensuring that default values remain escaped unless marked otherwise.

**Missing Mitigations:**
- **Content Security Policy (CSP):**
  There is no out‑of‑the‑box enforcement of CSP headers which could help block inline script execution even if unsafe content is injected.
- **Additional Backend Sanitization on “Safe” Properties:**
  Once a property is marked as safe, no further checks or validations are applied to its contents. Additional backend validation could be enforced even when the developer opts in to unsafe output.
- **Developer Warnings or Audit Logging:**
  There is no built‑in mechanism that warns developers or logs a potential risk when a property is marked safe and used in a context where malicious input might be embedded.

**Preconditions:**
- The component must expose an attribute that is rendered directly into the DOM without re‑escaping. This occurs only if the developer explicitly opts to output raw HTML (e.g., via Meta.safe or by using the “|safe” template filter).
- The reactive AJAX endpoint (commonly at a URL starting with `/message/`) must be publicly exposed so that an attacker can submit specially crafted input.
- The attacker must be able to control the input value that will be bound to a “safe” property (for example, via a reactive input field using `unicorn:model` or through direct manipulation of the AJAX payload).

**Source Code Analysis:**
- **HTML Sanitization Bypass:**
  In the code path (as evidenced by tests in `test_process_component_request.py`), the function that calls `sanitize_html` is not invoked when a property is marked as safe (via Meta.safe). In these cases, the value is passed along "as is" to the JSON serializer.
- **JSON Serialization:**
  The custom JSON `dumps` method (built on orjson) converts component state into a JSON structure. However, if a property is flagged as safe, its content bypasses further sanitization and is later merged into the DOM in the frontend JavaScript.
- **Component Rendering:**
  Within the templating tag (see tests in files like `test_unicorn_render*`), once the AJAX response is processed the DOM is updated. If the payload (containing, for example, `<script>…</script>`) is unescaped because the component property is safe, the browser will execute the script.
- **Visualization:**
  1. Component property “hello” is set with safe output (demonstrated in FakeComponentSafe).
  2. An AJAX “callMethod” or “syncInput” action sends a payload with `<script>alert('XSS triggered');</script>`.
  3. The serializer (using `orjson.dumps`) returns a JSON response where “hello” appears as the raw string value.
  4. The client’s rendering engine (using a script tag injected into the DOM) merges the output, resulting in unsanitized HTML rendered directly.

**Security Test Case:**
1. **Component Setup:**
   - Create a Unicorn component (e.g., “hello-world”) that includes a text input field bound to a property (e.g., “hello”).
   - In the component’s class, add a Meta class that marks “hello” as safe (similar to the FakeComponentSafe in the test files).
2. **Injecting the Malicious Payload:**
   - On a publicly accessible instance of your application, navigate to the component page.
   - In the “hello” input field, input a payload such as:
     `<script>alert('XSS triggered');</script>`
3. **Trigger an Update:**
   - Trigger the component update by either typing (which sends a “syncInput” action) or by invoking an action via a button click.
4. **Observation and Verification:**
   - Open the browser’s developer tools and inspect the updated DOM.
   - Verify that the inner HTML of the element corresponding to “hello” contains the unsanitized payload.
   - If correctly exploited, the browser should execute the injected script (an alert should pop up).
5. **Control Test:**
   - Remove the Meta.safe configuration (or avoid using the “|safe” template filter) so that the default sanitization occurs.
   - Repeat the injection; the payload should then be HTML‑escaped and rendered as text without executing.

```

This detailed vulnerability entry demonstrates how marking a component property as "safe" without additional backend sanitization can allow attacker-supplied input to be rendered unescaped, resulting in a high-severity XSS vulnerability.
