Below is the combined list of vulnerabilities in Markdown format. Note that duplicate issues have been merged and only those fully described as high‐severity (and realistic for an attacker) have been included.

---

# Combined Vulnerability List

---

## 1. Unescaped Output via Misuse of the Meta.safe Attribute (Cross‑Site Scripting via Misconfiguration)

**Description:**
- **Overview:** Although the framework automatically HTML‑encodes all output by default, developers can opt out by explicitly marking component properties as safe. This can be done either by adding property names to the component’s `Meta.safe` tuple **or** by applying Django’s `safe` filter in the template.
- **Step‑by‑step trigger:**
  1. **Component Setup:** A developer creates a component (for example, a view called `HelloWorldView` or a test component with a field like “message” or “description”) that exposes one or more properties.
  2. **Opt‑in to Unsafe Rendering:** The developer marks one or more of these properties as safe by including their names in the `Meta.safe` tuple (or by using the `|safe` filter in the template).
  3. **Supplying Malicious Input:** An attacker supplies malicious HTML/JavaScript (e.g. `<script>alert('XSS');</script>`) as the value of the safe‑marked property—typically through an AJAX call or user input that updates the property at runtime.
  4. **Bypassing Escaping:** Because the property is flagged as safe, the framework bypasses its usual automatic HTML‑escaping (using Django’s `mark_safe`) and includes the value verbatim in the JSON payload and eventually the DOM.
  5. **Execution:** When the component re‑renders in the browser, the injected script executes, triggering an XSS attack.

**Impact:**
- Successful exploitation results in arbitrary script execution in the victim’s browser. This can lead to session hijacking, theft of user credentials, data theft, drive‑by downloads, and even site defacement.

**Vulnerability Rank:**
- **High**

**Currently Implemented Mitigations:**
- The framework auto‑escapes all output by default—only properties explicitly opted‑in (via `Meta.safe` or the template’s safe filter) are rendered without escaping.
- The safe‑mechanism is opt‑in, meaning that by default no property is rendered unsanitized unless a developer deliberately changes that behavior.

**Missing Mitigations:**
- No independent sanitization is performed on data that is flagged as safe—if a developer opts out of auto‑escaping, there is no built‑in mechanism to check or clean user‑supplied input.
- There are no runtime warnings or static analysis checks to flag when a property that might receive dynamic, untrusted data is marked safe.
- The framework does not enforce additional sanitization (or input rejection) even when dangerous HTML elements are present.

**Preconditions:**
- A component’s developer must deliberately mark an attribute as safe (using either `Meta.safe` or the safe filter).
- The safe‑marked property is updated at runtime with attacker‑controlled input containing malicious payloads.

**Source Code Analysis:**
- **Rendering Lifecycle:** During the preparation of the “frontend context” (before serializing properties with functions like `serializer.dumps`), the code iterates over the list of safe‑marked fields and applies Django’s `mark_safe()`.
- **Bypass of Auto‑escaping:** In files such as `django_unicorn/components/unicorn_view.py`, after collecting public properties, the code checks if a given field is listed in `Meta.safe` and then bypasses Django’s standard auto‑escaping routines.
- **Injection Flow:** As a result, any string—even one containing malicious HTML—is embedded directly into the JSON payload that is ultimately merged into the DOM during an AJAX update, causing the malicious script to be executed.

**Security Test Case:**
1. **Component Creation:** Create a test component (for example, one with a “description” or “message” property) that binds its property value directly into its rendered template (e.g., using `{{ message }}` or `<div>{{ description }}</div>`).
2. **Opt‑in Unsafe Behavior:** In the component’s `Meta` class, add the property name (e.g., `"message"`) to the safe tuple, or alter the template to use the safe filter (e.g. `{{ message|safe }}`).
3. **Update via AJAX:** Use an AJAX call (or the designated endpoint) to update the property with a payload such as `<script>alert('XSS');</script>`.
4. **Observe the Response:** Confirm that the JSON response includes the dangerous content unescaped.
5. **Verify Exploitation:** In a browser, trigger the update and observe that the injected script executes, thereby confirming an XSS attack.

---

## 2. Insecure Output via the “safe” Template Filter on Component Variables

**Description:**
- **Overview:** Even when a component does not designate any property as safe through `Meta.safe`, a template designer might still bypass auto‑escaping by applying Django’s `safe` filter directly in the template.
- **Step‑by‑step trigger:**
  1. **Template Configuration:** A component is created and its template renders a variable using the safe filter (e.g., `<div>{{ message|safe }}</div>`).
  2. **Supplying Malicious Input:** An attacker (or any user with access to the publicly available component) submits an update for the “message” property containing a malicious payload such as `<script>alert('XSS')</script>`.
  3. **Bypass of Auto‑escaping:** Because the safe filter is used, the dangerous payload is not HTML‑escaped.
  4. **Resulting Execution:** When the component re‑renders, the malicious payload is directly embedded into the DOM, resulting in the execution of the attacker‑supplied script.

**Impact:**
- This vulnerability enables arbitrary JavaScript execution in the client’s browser. The outcome can include session hijacking, data theft, drive‑by downloads, or even site defacement.

**Vulnerability Rank:**
- **High**

**Currently Implemented Mitigations:**
- Django templates automatically escape variables by default, and the safe filter is only applied when explicitly added by a developer.

**Missing Mitigations:**
- The framework does not add any further sanitization for data after the safe filter is applied—protection relies entirely on the developer’s discipline and awareness.
- There is no static analysis or runtime check to warn if user‑controlled input is rendered via the safe filter.

**Preconditions:**
- The component’s template must include the safe filter when rendering a variable.
- The rendered variable must receive untrusted, user‑controlled input that may contain malicious payloads.

**Source Code Analysis:**
- **Template Behavior:** Documentation and code samples indicate that when the safe filter is applied (e.g., `{{ message|safe }}`), Django’s auto‑escaping is bypassed.
- **Data Flow:** Despite the backend logic (including JSON serialization) working correctly, the use of the safe filter ensures that any untrusted input is delivered as raw HTML to the client, thus introducing a potential XSS vulnerability.

**Security Test Case:**
1. **Component and Template Setup:** Create a test component with a property (e.g., “message”) and render it in the template using the safe filter (e.g., `<div>{{ message|safe }}</div>`).
2. **Injection via AJAX:** Initiate an AJAX update (or use the appropriate message endpoint) that sets the property’s value to `<script>alert('XSS')</script>`.
3. **JSON Verification:** Check that the JSON response from the view contains the payload without any escaping.
4. **Script Execution:** Open the component in a browser to see if the injected script executes, thereby confirming the vulnerability.

---

## 3. Unsanitized Nested Property Update Allowing XSS

**Description:**
- **Overview:** The framework allows updating nested properties using dot‑notation (for example, `"nested.field"`). While non‑nested properties are auto‑escaped by default, if a nested property is explicitly marked as safe (either via `Meta.safe` or the safe filter), no additional sanitization is performed during updates via AJAX.
- **Step‑by‑step trigger:**
  1. **Component Setup with Nested Properties:** A developer creates a component that defines a nested property (for example, `"property_one.nested_property_one"`).
  2. **Opt‑in to Unsafe Rendering for Nested Data:** The nested property is either added to the `Meta.safe` tuple or rendered using the safe filter.
  3. **Supplying Malicious Input:** An attacker sends an AJAX request to update the nested property with a malicious payload such as `<script>alert('XSS');</script>`.
  4. **Direct Update without Sanitization:** The function responsible (typically `set_property_value` in `django_unicorn/views/action_parsers/utils.py`) splits the nested property name by “.” and updates the nested value using Python’s `setattr` without performing additional sanitization.
  5. **Resulting Execution:** The unsanitized malicious payload is later rendered into the DOM, causing the attack script to be executed.

**Impact:**
- The injection of dangerous HTML into nested output can result in arbitrary JavaScript execution. This exposes users to risks such as session hijacking, data leakage, and further XSS‑related attacks.

**Vulnerability Rank:**
- **High**

**Currently Implemented Mitigations:**
- The framework’s default behavior is to auto‑escape all output. However, this safeguard is bypassed when a developer explicitly marks a nested property as safe.

**Missing Mitigations:**
- There is no additional sanitization or validation step for nested property updates performed via dot‑notation.
- The system does not enforce warnings or static analysis checks to determine if nested properties containing untrusted input are being flagged as safe.

**Preconditions:**
- A nested property must be explicitly opted‑out of auto‑escaping (via inclusion in `Meta.safe` or by using the safe filter).
- The attacker must have the ability to update the nested property via an AJAX request or similar mechanism.

**Source Code Analysis:**
- **Nested Update Flow:** In the function `set_property_value` (located in `django_unicorn/views/action_parsers/utils.py`), the property name is split on the “.” character.
- **Lack of Sanitization:** As the function traverses the nested structure, it applies the update directly (using helper functions or Python’s `setattr`) without performing extra sanitization.
- **Injection Result:** Because the nested property was marked as safe, the malicious payload is embedded verbatim in the component’s output, which will be rendered directly into the DOM.

**Security Test Case:**
1. **Component Definition:** Create a component that defines a nested property (for example, `"property_one.nested_property_one"`).
2. **Mark as Safe:** In the component’s `Meta` class, mark the nested property as safe so that it bypasses auto‑escaping.
3. **Malicious Update:** Use an AJAX call (or the relevant Unicorn message endpoint) to update the nested property with a payload such as `<script>alert('XSS');</script>`.
4. **Render and Verify:** Render the component and capture the resulting HTML output.
5. **Confirm Vulnerability:** Verify that the JSON payload (and the subsequently rendered DOM) contains the unsanitized malicious payload and that the injected script executes in the browser.

---

*End of Combined Vulnerability List.*
