# Combined Vulnerability List

Below is the deduplicated and combined list of vulnerabilities. Although originally described from slightly different perspectives (e.g. component field versus component property, raw mode versus safe output), they all stem from the same core issue: when developers intentionally bypass HTML auto‑escaping (by opting in via the `Meta.safe` tuple or using the Django “safe” filter), attacker‑controlled input may be injected into the DOM unescaped, leading to Cross‑Site Scripting (XSS).

---

## 1. Cross‑Site Scripting (XSS) via Unsafe "Safe" Rendering in Django Unicorn Components

### Description
When a developer marks one or more component fields or properties as safe—either by listing them in the component’s `Meta.safe` configuration or by using the Django “safe” filter in a template—the automatic HTML auto‑escaping is bypassed. In this mode, if an attacker can supply a malicious payload, that payload is stored unmodified and later injected directly into the DOM during a reactive update, triggering the execution of arbitrary JavaScript.

**Step‑by‑Step Trigger:**
1. **Component Configuration / Opt‑in:**
   - A developer creates or modifies a Django Unicorn component and explicitly declares a field or property (e.g. `dangerous_content` or `something_safe`) as safe by including its name in the `Meta.safe` tuple or by rendering the field using the Django “safe” filter.
   - *Example:*
     ```python
     class TestXSSComponent(UnicornView):
         dangerous_content = "default content"

         class Meta:
             safe = ("dangerous_content",)
     ```
2. **Malicious Input Delivery:**
   - An attacker (or untrusted user) supplies a payload (for example, `<script>alert('XSS');</script>`) via an AJAX call, a form submission, or through another reactive mechanism (such as via a `unicorn:model` binding).
3. **Bypassing Escaping / Raw Output:**
   - Because the field or property is marked as safe, the framework bypasses its normal HTML‑escaping. During the serialization (in functions like `_get_model_dict` and `_json_serializer`) or when processing component updates (via helpers such as `set_property_value`), the provided value is passed through without sanitization.
4. **Dynamic Rendering:**
   - In the reactive update cycle, the unsanitized payload is merged into the frontend context and later re‑rendered on the client’s browser. Since the raw value is wrapped with Django’s `mark_safe` (or simply left unescaped), the payload is inserted directly into the DOM.
5. **Script Execution:**
   - When the browser processes the updated HTML, the malicious `<script>` tag is executed, giving the attacker the ability to run arbitrary JavaScript.

### Impact
- **Arbitrary JavaScript Execution:** An attacker can execute any JavaScript in the context of the affected user’s browser.
- **Session Hijacking & Data Theft:** This can lead to stolen session cookies, hijacked sessions, stealing user credentials, or manipulation of sensitive data.
- **Widespread Risk:** Since Django Unicorn components may be used extensively across an application, a single unsafe “safe” configuration may have significant exposure.

### Vulnerability Rank
**High**

### Currently Implemented Mitigations
- **Default Auto‑escaping:**
  - By default, Django’s template engine and Unicorn’s serializer auto‑escape component output. Only properties intentionally opted in (via the safe mechanism) bypass escaping.
- **Explicit Developer Opt‑In:**
  - The framework requires an explicit developer action (via `Meta.safe` or using the `safe` filter), ensuring that raw output is not the default behavior.
- **Sanitization during Serialization:**
  - In normal operation (for properties not marked safe), methods like `_get_model_dict` and `_json_serializer` process data through Django’s default JSON encoder and escaping routines.
- **Documentation and Warnings:**
  - Developer documentation warns about the risks associated with opting into raw output.

### Missing Mitigations
- **Runtime Warning or Audit:**
  - There is no built‑in mechanism that logs or warns developers when a field/property is marked as safe.
- **Secondary Sanitization:**
  - Once a property is designated safe, no additional or configurable re‑sanitization is applied before injection into the DOM.
- **Strict Input Validation / CSP Enforcement:**
  - There is a lack of granular validation on inputs flagged as safe, and no enforced strict Content Security Policy (CSP) that might mitigate the explosive consequences of an XSS attack.

### Preconditions
- **Opt‑in Configuration:**
  - The component must have at least one field or public property explicitly added to the `Meta.safe` tuple or rendered with the `safe` filter.
- **Attacker-Controlled Input:**
  - An attacker must be able to control the value of the field/property. This control is typically granted through AJAX calls, form submissions, or other reactive client interactions.
- **Unmodified Template Rendering:**
  - The component’s template must output the field/property without applying additional filters that might otherwise perform escaping.

### Source Code Analysis
- **Serialization Bypass:**
  - In `django_unicorn/serializer.py`, functions such as `_get_model_dict` and `_json_serializer` are responsible for serializing component properties. When a property is flagged as safe, the value bypasses normal sanitization routines.
- **Property Update Flow:**
  - The update routines (e.g., in `django_unicorn/views/action_parsers/utils.py` and `call_method.py`) handle incoming JSON payloads. If the property is marked as safe, the corresponding utility functions (like `set_property_value`) insert the value directly into the component instance.
- **Final Rendering:**
  - In the final rendering phase (for example, within the component update flow in `django_unicorn/views/__init__.py`), the framework checks the `Meta.safe` tuple. For any property present there, Django’s `mark_safe` is applied, and the raw value is injected into the DOM without further escaping.

*Visualization of the Flow:*
```
[Component Configuration]
         │
         ▼
[Developer marks a property safe (Meta.safe / safe filter)]
         │
         ▼
[Attacker supplies malicious payload via AJAX / form]
         │
         ▼
[Serializer bypasses escaping (e.g. _json_serializer)]
         │
         ▼
[Property update routine sets property value without re‑sanitization]
         │
         ▼
[Final rendering calls mark_safe and injects raw HTML into DOM]
         │
         ▼
[Browser executes injected <script> code]
```

### Security Test Case
1. **Setup:**
   - Create a test component (e.g. `TestXSSComponent`) with a property called `dangerous_content`:
     ```python
     class TestXSSComponent(UnicornView):
         dangerous_content = "default content"

         class Meta:
             safe = ("dangerous_content",)
     ```
   - Create a corresponding template (e.g. `test_xss_component.html`) that simply renders the property:
     ```html
     <div>
       {{ dangerous_content }}
     </div>
     ```
2. **Attack:**
   - Use a browser’s developer console or an HTTP testing client to send an AJAX POST request to the Unicorn endpoint that updates the property.
   - In the JSON payload, set:
     ```json
     {
       "dangerous_content": "<script>alert('XSS');</script>"
     }
     ```
   - Ensure that the request is accepted (with proper CSRF protection and checksum if applicable).
3. **Verification:**
   - Inspect the AJAX JSON response and the resulting updated HTML.
   - Confirm that the rendered HTML contains the raw `<script>alert('XSS');</script>` string without any escaping.
   - Use browser developer tools or an automated headless browser to verify that the injected script actually executes (e.g. that an alert appears), confirming the vulnerability.

---

*Note:* This combined vulnerability entry represents a critical issue resulting from rendering user-controlled data without proper sanitization. It underscores the need for additional runtime mitigations and input validations, as well as enforcing stricter security policies when using features that bypass auto‑escaping.
