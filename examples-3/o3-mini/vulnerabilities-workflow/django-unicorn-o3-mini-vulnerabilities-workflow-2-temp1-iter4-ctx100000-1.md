- **Vulnerability Name:** Insecure “Safe” Marking Allowing XSS via Component Fields
  **Description:**
  • Developers may “opt‑in” to bypass Django’s autoescaping by marking a component property as safe (for example, by listing it in the component Meta‑safe tuple or by using the “|safe” filter).
  • When a field is marked safe, its value is inserted into the HTML or a JSON initialization script (via functions like `set_property_from_data`) without any further output‑encoding.
  • Several tests (for example, in `tests/views/test_process_component_request.py` – see `test_safe_html_entities_not_encoded`) demonstrate that if an attacker submits a payload such as `"<script>alert('XSS');</script>"` into a field that is marked safe, the payload is rendered verbatim in the final DOM.
  • An attacker exploiting this flaw can inject malicious HTML/JavaScript that executes when the component re‑renders.
  **Impact:**
  • The injected script may run in the context of the user’s session, potentially leading to session hijacking, defacement, or the theft of sensitive data.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  • By default, all component property data is autoescaped during Django template rendering.
  • When generating the JSON initialization script, Django Unicorn runs the data through a helper (`sanitize_html`) that performs basic character translations.
  • However, these precautions are bypassed when a field is explicitly marked as safe.
  **Missing Mitigations:**
  • There is no additional, context‑sensitive output encoding or runtime sanitization applied to fields that have been opted in as safe.
  • No extra whitelist filtering (or similar mechanism) ensures that even “safe” fields cannot contain dangerous markup.
  **Preconditions:**
  • A component is designed so that a developer marks one or more properties as safe (via Meta configuration or the safe filter).
  • The affected safe property is bound to user‑supplied input (for example, via an AJAX‑driven input or form field).
  **Source Code Analysis:**
  • In the Unicorn template tag implementation (found in `django_unicorn/templatetags/unicorn.py`), when constructing the context for rendering the component, any field marked as safe is not re‑passed through autoescaping.
  • The rendering routines and property‑updating functions (for example, those invoked via `set_property_from_data`) update the property directly with request data. This behavior is demonstrated by tests such as `test_safe_html_entities_not_encoded` where the unsanitized payload `<b>test1</b>` appears in the DOM.
  **Security Test Case (Step‑by‑Step):**
  1. Create a custom Unicorn component (for example, “SafeInputComponent”) that defines a property (e.g. `hello`) and marks it as safe via its Meta configuration.
  2. Bind an input element in the component’s template to the `hello` property.
  3. From an external client (or via an AJAX simulator), submit a payload such as
     `"<script>alert('XSS');</script>"`
     into the input bound to `hello`.
  4. Trigger an action (or otherwise cause the component to re‑render) so that the new value is output into the DOM.
  5. Using browser developer tools, inspect the rendered HTML to verify that the payload is inserted verbatim (i.e. without escaping).
  6. Confirm that the injected script executes (e.g. an alert dialog pops up), thereby proving an XSS vulnerability.
