- **Vulnerability Name:** Cross‑Site Scripting (XSS) via Unsanitized Component Output (Raw Mode)
  - **Description:**
    Django‑unicorn components automatically escape output when rendering by default. However, if a developer explicitly “opts in” to raw output—for example, by declaring a component property in a Meta‑safe tuple or using the template’s “safe” filter—the framework calls Django’s `mark_safe` on that value during response generation. An attacker who supplies a malicious payload via any reactive input (such as via a field bound with `unicorn:model`, a syncInput action, or through a call‑method that uses property setters) can have that payload stored in a property that is rendered without escaping. When the component is re‑rendered (for instance, during an AJAX update), the injected payload is merged into the DOM (using libraries like morphdom) and executed in the browser.

    **Step‑by‑step attack scenario:**
    1. The attacker discovers that a particular reactive component uses a property (for example, “user_input”) that is declared as raw—either because it is included in the component’s Meta‑safe tuple or rendered using the template filter “safe.”
    2. The attacker submits a specially crafted payload (e.g.
       `"</div><script>alert('XSS');</script>"`) via a form field or an AJAX request that sets the property’s value.
    3. The framework’s update mechanisms (via functions such as `set_property_from_data` or `set_property_value` as shown in multiple test files) update the property on the component without sanitizing the payload.
    4. During the subsequent re‑render, the component “marks” the property as safe (using Django’s `mark_safe`) and the payload is injected into the DOM unescaped.
    5. Finally, when the DOM is diffed and merged by the client–side JavaScript, the injected script executes in the browser.

  - **Impact:**
    Successful exploitation permits an attacker to execute arbitrary JavaScript within the context of the vulnerable site. This may result in session hijacking, defacement, data exfiltration, or additional client‐side attacks.

  - **Vulnerability Rank:** High

  - **Currently Implemented Mitigations:**
    - **Default Escaping:** Django’s template engine auto‑escapes variables by default so that ordinary component properties render safely.
    - **Opt‑in Mechanism:** Django‑unicorn requires developers to explicitly opt into raw (unescaped) output (via the Meta‑safe tuple or the |safe filter) so that by default properties are not marked as safe.
    - **Documentation:** The framework documentation clearly explains the trade‑offs of opting into raw output.

  - **Missing Mitigations:**
    - **Additional Sanitization:** There is no supplementary filtering or sanitization applied to properties that are marked as safe—even if such properties contain user–controlled data.
    - **CSP Enforcement:** The framework does not enforce a strong Content Security Policy (CSP) that could mitigate accidental XSS even if raw output is used.
    - **Granular Warnings/Validation:** There is no built‑in mechanism to warn developers or validate that values destined for “safe” output do not contain malicious content.

  - **Preconditions:**
    - The application must utilize a reactive component that accepts user–supplied input either via form fields, AJAX requests (as seen in test modules like `test_call_method_multiple.py` and `test_sync_input.py`), or other dynamic updates.
    - A component property is intentionally or inadvertently marked for raw output (for example, via Meta‑safe declarations or usage of the template “safe” filter).
    - An attacker must be able to control the input delivered to the component (e.g. through a publicly accessible endpoint) thereby causing the malicious payload to be stored and rendered.

  - **Source Code Analysis:**
    - **Component Response and Property Update:**
      In files such as `django_unicorn/views/action_parsers/utils.py` and `django_unicorn/views/action_parsers/call_method.py`, the framework processes incoming JSON messages. The helper utilities (e.g. `set_property_from_data` in tests like `test_set_property_from_data*.py` and `set_property_value` in `call_method.py`) update component properties based on user–supplied data without additional sanitization if the property is opted into raw output.
    - **Marking as Safe:**
      In the response–generation logic (referenced in the documentation), the framework iterates over public component properties and, if the property is configured as “safe” via a Meta‑safe tuple or through the use of the “safe” filter, it calls Django’s `mark_safe`. Consequently, if the property’s value contains an attacker’s script snippet, it bypasses Django’s auto‑escaping.
    - **Test Evidence:**
      Extensive tests (e.g. in files like `test_call_method_multiple.py`, `test_set_property_from_data.py`, and `test_get_property_value.py`) show data flowing from JSON payloads into properties. Although these tests currently assert correct behavior for valid updates, the same code paths would directly inject unsanitized strings if the property is marked as safe.

  - **Security Test Case:**
    1. **Create a Test Component:**
       - Define a simple Django‑unicorn component (e.g., `XSSDemoView`) with a property such as `user_input` that will be rendered in its template.
       - In the component class, either include an inner Meta class that adds `user_input` to the safe tuple or use the template’s “safe” filter when outputting the value.
    2. **Render the Component and Identify Baseline Output:**
       - Render the component normally and confirm that the property is initially rendered in an escaped form.
    3. **Inject Malicious Input:**
       - Using a test client or browser, send an AJAX (or syncInput) request that sets the `user_input` property to a payload such as:
         `"</div><script>alert('XSS');</script>"`
       - This payload should be delivered as part of the JSON data that updates the component.
    4. **Trigger a Reactive Update:**
       - Cause the component to re‑render (as in tests demonstrated in `test_message_*` files).
       - Confirm that the property update is processed via the call‑method or sync input mechanism.
    5. **Inspect the Response and Browser Behavior:**
       - Examine the AJAX response and the resulting DOM (using browser developer tools) to verify that the malicious payload is inserted unescaped.
       - Confirm that the injected script (e.g. the alert box) actually executes in the browser.
    6. **Conclusion:**
       - A successful test confirms that when a property is marked as safe, unsanitized user input can drive XSS through the reactive component update pipeline.
