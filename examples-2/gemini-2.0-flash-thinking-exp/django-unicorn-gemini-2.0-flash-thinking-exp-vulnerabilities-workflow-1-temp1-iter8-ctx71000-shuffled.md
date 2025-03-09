## Combined Vulnerability List

### 1. Code Injection Vulnerability via Action Arguments Parsing

- **Description:**
    - An attacker can inject arbitrary Python code through action arguments due to insecure parsing of arguments in the `django-unicorn` template tag and method call processing.
    - **Step-by-step trigger:**
        1. Identify a component in the application that uses actions and accepts arguments from the template.
        2. Craft a malicious payload as an argument to a component action. This payload will contain Python code intended for execution on the server.
        3. Trigger the action from the frontend, sending the malicious payload as an argument.
        4. The `django-unicorn` backend will parse and evaluate this payload using `ast.literal_eval` or similar functions without sufficient sanitization or validation.
        5. If successful, the injected Python code will be executed on the server within the context of the Django application.

- **Impact:**
    - **Critical**. Successful code injection can lead to complete server takeover, data breach, modification of application data, and other severe security breaches. An attacker can execute arbitrary commands on the server, potentially gaining full control of the application and its underlying infrastructure.

- **Vulnerability rank:** critical

- **Currently implemented mitigations:**
    - None identified that prevent code injection through argument parsing. The project relies on `ast.literal_eval` and similar mechanisms which might be vulnerable if not used carefully. HTML sanitization is present in utility functions, but it does not prevent code injection on the backend as it's not applied to action arguments.

- **Missing mitigations:**
    - Input sanitization and validation for action arguments on the backend to prevent execution of arbitrary code.
    - Use of secure parsing methods that do not evaluate arbitrary Python code from user input. Consider using a safer approach to convert string representations to Python types, or strictly limit the types and formats of arguments allowed.
    - Implement a strict allowlist for argument types and values if dynamic argument parsing is necessary.

- **Preconditions:**
    - The application must use `django-unicorn` components that define actions and accept arguments from the frontend.
    - The attacker must be able to trigger these actions with crafted arguments.

- **Source code analysis:**
    - The vulnerability is located in how `django-unicorn` parses action arguments, potentially using `ast.literal_eval` to convert strings to Python types.
    - The `eval_value` function in `django_unicorn/call_method_parser.py` uses `ast.literal_eval` which can be dangerous.
        ```python
        @lru_cache(maxsize=128, typed=True)
        def eval_value(value):
            """
            Uses `ast.literal_eval` to parse strings into an appropriate Python primitive.
            ...
            """
            try:
                value = ast.literal_eval(value)
            except SyntaxError:
                value = _cast_value(value)
            return value
        ```
    - `django_unicorn/templatetags/unicorn.py` parses arguments and kwargs in the `unicorn` templatetag. The parsing logic in `parse_kwarg` and `UnicornNode.render` needs careful review for insecure deserialization or code execution vulnerabilities.
    - Files like `django_unicorn/views/objects.py` show action processing in the `ComponentRequest` class, where `action_queue` is processed.

- **Security test case:**
    - **Vulnerability Test Name:** Code Injection via Action Arguments
    - **Test Description:** Attempt to execute arbitrary Python code on the server by injecting a malicious payload through a component action argument.
    - **Step-by-step test:**
        1. Deploy a Django application with `django-unicorn` enabled and a component that defines an action accepting string arguments, for example a component with method:
            ```python
            def action_with_arg(self, arg1):
                return os.system(arg1) #Insecure example, DO NOT USE IN PRODUCTION
            ```
            and template:
            ```html
            <button unicorn:click="action_with_arg('echo vulnerable')">Trigger Vulnerability</button>
            ```
        2. Access the page containing this component in a web browser.
        3. Open browser developer tools to intercept network requests (or use a proxy like Burp Suite).
        4. Click the "Trigger Vulnerability" button.
        5. Observe the network request sent to the `django-unicorn` endpoint.
        6. Modify the action argument in the request payload to a malicious Python command, such as: `'__import__("os").system("id")'` or `'__import__("subprocess").run(["touch", "/tmp/pwned"])'`. URL-encode or properly escape the payload if needed.
        7. Send the modified request to the server.
        8. Check the server logs or application behavior to confirm if the injected command (`id` or `touch /tmp/pwned` in examples) was executed.
        9. If the command is successfully executed, it confirms the code injection vulnerability.

### 2. Object Injection via Type Hinted Method Arguments and Properties

- **Description:**
    - An attacker can achieve object injection by sending crafted JSON requests to the `/message/` endpoint. This vulnerability is triggered when a component method accepts an argument with a class type hint or when updating a component property with a class type hint.
    - **Step-by-step trigger:**
        1. An attacker sends a crafted JSON request to the `/message/` endpoint.
        2. The request is designed to trigger a component method that accepts an argument with a class type hint or to update a component property with a class type hint.
        3. The attacker manipulates the `payload` within the request, specifically crafting the method arguments or property value as a JSON object.
        4. The `cast_value` function, when encountering a class type hint and a dictionary-like value, attempts to instantiate the hinted class using `_type_hint(**value)` or `_type_hint(value)`.
        5. If the constructor of the instantiated class performs actions with security implications, or if the instantiated object is misused later, a vulnerability is triggered, leading to remote code execution or arbitrary object manipulation.
        6. This vulnerability is also applicable to component properties updated via `syncInput` actions, using the same vulnerable `cast_attribute_value` and `cast_value` chain.

- **Impact:**
    - **Critical**: In scenarios leading to remote code execution.
    - **High**: If direct RCE is not achieved, arbitrary object manipulation, information disclosure, or other significant security breaches can occur.

- **Vulnerability rank:** critical

- **Currently implemented mitigations:**
    - Checksum validation on the request body: Prevents tampering with the overall request data, but not object injection within the data itself.
    - Type casting using `cast_value`: Ironically, this function facilitates the vulnerability.

- **Missing mitigations:**
    - Input validation and sanitization of user-provided data before class instantiation.
    - Restriction of Type Hint Classes: Limit permissible classes for type hinting, ideally to primitive types or a whitelist of safe classes. Disabling automatic class instantiation from arbitrary type hints is recommended.
    - Context-Aware Input Handling: Implement safer deserialization logic for complex types, avoiding direct instantiation from raw user data.

- **Preconditions:**
    - A Django Unicorn component with:
        - A method with a class type hinted argument.
        - A property with a class type hint updatable via user input.
    - The type hinted class must have a constructor susceptible to object injection attacks.

- **Source code analysis:**
    1. **`django_unicorn/typer.py` -> `cast_value`**: Central to the vulnerability, it instantiates classes based on type hints and user input.
        ```python
        def cast_value(type_hint: Any, value: Any) -> Any:
            ...
            elif is_dataclass(type_hint):
                value = type_hint(**value) # Vulnerable line
            ...
            return value
        ```
    2. **`django_unicorn/components/unicorn_view.py` -> `_set_property`**: Uses `cast_attribute_value` which calls `cast_value`, making property setting vulnerable.
    3. **`django_unicorn/views/action_parsers/call_method.py` -> `_call_method_name`**: Uses `cast_value` for method arguments, leading to potential object injection.

        ```mermaid
        graph LR
            A[User Request] --> B(/message/ endpoint)
            B --> C[ComponentRequest]
            C --> D[Action Parsing (_call_method_name or _set_property)]
            D --> E[cast_value in typer.py]
            E --> F[Class Instantiation with User Data (_type_hint(**value) or _type_hint(value))]
            F --> G[Potential Object Injection]
        ```

- **Security test case:**
    - **Vulnerability Test Name:** Object Injection via Type Hinting
    - **Test Description:** Attempt to execute arbitrary code by injecting a malicious object through a type-hinted method argument.
    - **Step-by-step test:**
        1. Vulnerable Component Code (`example/unicorn/components/vulnerable_component.py`):
            ```python
            from django_unicorn.components import UnicornView

            class CustomObject:
                def __init__(self, command):
                    import os
                    os.system(command) # Vulnerable!

            class VulnerableView(UnicornView):
                def vulnerable_method(self, obj: CustomObject):
                    pass
            ```
        2. Vulnerable Component Template (`example/templates/unicorn/vulnerable_component.html`):
            ```html
            <button unicorn:click="vulnerable_method({ 'command': 'echo vulnerable' })">Trigger Vulnerability</button>
            ```
        3. Deploy the Django application with the vulnerable component and view.
        4. Access the `/vulnerable` page in a browser to render the component.
        5. Identify the component ID.
        6. Craft a POST request using `curl` to send a message to the component:
              ```bash
              curl -X POST -H "Content-Type: application/json" -d '{"data":{},"checksum":"<CHECKSUM>","id":"testcomponentid","epoch":1678886400,"actionQueue":[{"type":"callMethod","payload":{"name":"vulnerable_method(obj={\"command\":\"touch /tmp/unicorn_vuln\"})"}}]}' http://your-app-domain/message/example.unicorn.components.vulnerable_component.VulnerableView
              ```
              Replace `<CHECKSUM>` with the SHA256 checksum of `{"data":{}}`.
        7. After sending the request, access the server and check for the file `/tmp/unicorn_vuln`. If the file exists, it indicates successful command execution due to object injection.

### 3. Remote Code Execution via Method Call Parsing

- **Vulnerability name:** Remote Code Execution via Method Call Parsing
- **Description:**
    - An attacker can execute arbitrary Python code by exploiting the `parse_call_method_name` function, which uses `ast.parse` in `eval` mode on user-provided input.
    - **Step-by-step trigger:**
        1. An attacker sends a crafted POST request to the `/message/{component_name}` endpoint.
        2. The request includes a `callMethod` action with a malicious `name` payload.
        3. The `parse_call_method_name` function processes the `name` payload using `ast.parse` with `eval` mode.
        4. By injecting malicious Python code into the `name` payload, the attacker achieves arbitrary Python code execution on the server.

- **Impact:** Remote Code Execution (RCE). Full system compromise, data exfiltration, and denial of service are possible.

- **Vulnerability rank:** Critical

- **Currently implemented mitigations:**
    - Checksum validation of the request data: Ensures data integrity but does not prevent code injection through vulnerable parsing logic.

- **Missing mitigations:**
    - Input sanitization and validation for `call_method_name` in `parse_call_method_name`.
    - Avoid using `ast.parse` with `eval` mode for user input; use safer parsing techniques or whitelisting.

- **Preconditions:**
    - A publicly accessible Django application using `django-unicorn`.
    - The application must handle `callMethod` actions.

- **Source code analysis:**
    ```python
    # File: django_unicorn/call_method_parser.py
    @lru_cache(maxsize=128, typed=True)
    def parse_call_method_name(
        call_method_name: str,
    ) -> Tuple[str, Tuple[Any, ...], Mapping[str, Any]]:
        """
        Parses the method name from the request payload into a set of parameters to pass to
        a method.
        ...
        """
        tree = ast.parse(method_name, "eval") # Vulnerable code: ast.parse with mode='eval'
        # ...
    ```
    - `parse_call_method_name` in `django_unicorn/call_method_parser.py` uses `ast.parse(method_name, "eval")`.
    - `method_name` is directly from the request payload's `name` field in `callMethod` action.
    - `ast.parse(..., mode='eval')` is dangerous with untrusted input, enabling arbitrary code execution.

- **Security test case:**
    - **Vulnerability Test Name:** RCE via `ast.parse` in `callMethod`
    - **Test Description:** Execute arbitrary Python code by injecting malicious code into the `callMethod` name payload.
    - **Step-by-step test:**
        1. Setup a Django project with django-unicorn and a publicly accessible view with a Unicorn component.
        2. Create a simple Unicorn component method (e.g., `test_method`).
        3. Using `curl`, send a POST request to `/message/{component_name}` with `Content-Type: application/json`.
        4. Include the JSON payload:
        ```json
        {
          "id": "testComponentId",
          "name": "testComponentName",
          "epoch": 1678886400,
          "data": {},
          "checksum": "...",
          "actionQueue": [
            {
              "type": "callMethod",
              "payload": {
                "name": "import os; os.system('touch /tmp/unicorn_rce');test_method"
              }
            }
          ]
        }
        ```
        - Replace `"..."` with the correct checksum.
        5. Send the request.
        6. Check the server for the creation of `/tmp/unicorn_rce`. If present, RCE is confirmed.

### 4. Cross-Site Scripting (XSS) via Unsanitized Component Properties

- **Vulnerability name:** Cross-Site Scripting (XSS) via Unsanitized Component Properties
- **Description:**
    -  Unsanitized component properties, especially when bound using `unicorn:model` and rendered in templates without proper escaping, can lead to XSS. This is exacerbated when developers mistakenly use the `safe` attribute or template filters like `|safe` on user-controlled data.
    - **Step-by-step trigger:**
        1. An attacker sends a crafted `syncInput` message to modify a component's property with a malicious JavaScript payload.
        2. `set_property_value` updates the component's property without HTML sanitization.
        3. If the template renders this property without escaping (e.g., `{{ property }}` or misused `{{ property|safe }}` or `{% filter safe %}`), the payload is rendered as raw HTML.
        4. The attacker-controlled JavaScript executes in the user's browser, leading to XSS.

- **Impact:**
    - An attacker can execute arbitrary JavaScript code in the context of the user's browser, leading to session hijacking, cookie theft, website defacement, or malicious redirects.

- **Vulnerability rank:** high

- **Currently implemented mitigations:**
    - Django Unicorn defaults to HTML encoding all component field values to prevent XSS.
    - Developers must explicitly use `Meta.safe` to disable encoding for specific fields.

- **Missing mitigations:**
    - Automatic HTML sanitization for component properties set via `syncInput`.
    - Clearer documentation warnings against using `safe` with user-controlled data without backend sanitization.
    - No mechanism to automatically detect potential XSS when `safe` is used.

- **Preconditions:**
    - A Unicorn component with a property rendered in the template without HTML escaping.
    - The property is modifiable via `syncInput` (e.g., `unicorn:model`).
    - Developers might misuse `safe` attribute or template filters like `|safe`.

- **Source code analysis:**
    1. **`django_unicorn\views\action_parsers\sync_input.py`:** `handle` function processes `syncInput` and calls `set_property_value`.
    2. **`django_unicorn\views\action_parsers\utils.py`:** `set_property_value` sets the property value directly using `setattr` without sanitization.
    3. **`django_unicorn\typer.py`:** `cast_value` performs type casting but no HTML sanitization.
    4. **`django_unicorn\components\unicorn_template_response.py`:** `_desoupify` *unescapes* HTML, negating default encoding and increasing XSS risk.

- **Security test case:**
    - **Vulnerability Test Name:** XSS via Unsanitized Property
    - **Test Description:** Inject malicious JavaScript via `syncInput` and render unsanitized property to trigger XSS.
    - **Step-by-step test:**
        1. Create a Unicorn component with a string property `name` and render it using `{{ name }}`.
            ```html
            <div>
                <input type="text" unicorn:model="name">
                <div id="output">{{ name }}</div>
            </div>
            ```
        2. Open the page in a browser.
        3. In the input field, enter `<img src=x onerror=alert('XSS')>`.
        4. Observe the `alert('XSS')` dialog box appears.
        5. Verify in browser's developer tools that `div#output` contains the raw, unsanitized payload.

### 5. Django Model and QuerySet Serialization Information Disclosure

- **Vulnerability Name:** Django Model and QuerySet Serialization Information Disclosure
- **Description:**
    - Django Unicorn automatically serializes entire Django Models and QuerySets bound to component fields with `unicorn:model`, exposing all fields in the HTML source within `<script>` tags.
    - **Step-by-step trigger:**
        1. Define a Django Unicorn component with a field as a Django Model or QuerySet (e.g., `user = User.objects.first()`).
        2. Use `unicorn:model` in the template to bind to a field of this model (e.g., `<input unicorn:model="user.username">`).
        3. Django Unicorn serializes the *entire* `user` object to JSON during rendering.
        4. This JSON data is embedded in the HTML source within a `<script type="application/json" id="unicorn:data:{component_id}">` tag.
        5. An attacker views the HTML source code and extracts the full serialized model data, including sensitive fields.

- **Impact:** High. Exposure of sensitive backend data, including PII, confidential business data, or internal system details, depending on the models exposed.

- **Vulnerability Rank:** High

- **Currently implemented mitigations:**
    - Documentation warns about this behavior and recommends using `Meta.exclude` or `Meta.javascript_exclude`.
    - Documentation suggests using `.values()` on QuerySets to select specific fields.

- **Missing Mitigations:**
    - No default protection against automatic full serialization of models/querysets.
    - No built-in mechanism to sanitize or control serialized data by default.

- **Preconditions:**
    - Django Unicorn is used in a Django project.
    - A component renders and defines a Django Model/QuerySet field.
    - This field is bound using `unicorn:model` in the template.

- **Source Code Analysis:**
    - `django_unicorn.components.unicorn_template_response.UnicornTemplateResponse.render` and `django_unicorn.views.__init__.py` handle rendering.
    - `UnicornView.get_context_data()` calls `self._attributes()` to get component attributes.
    - `UnicornView._attributes()` collects all public attributes, including models/querysets.
    - `UnicornView.get_frontend_context_variables()` serializes attributes to JSON using `django_unicorn.serializer.dumps`, serializing all model fields by default.
    - Serialized JSON is embedded in HTML within `<script type="application/json" id="unicorn:data:{component_id}">` by `UnicornTemplateResponse.render`.

- **Security Test Case:**
    - **Vulnerability Test Name:** Model Serialization Data Exposure
    - **Test Description:** Demonstrate exposure of sensitive model data by inspecting HTML source.
    - **Step-by-step test:**
        1. Define a Django model `SensitiveData` with `public_field`, `secret_field_1`, `secret_field_2`. Populate with sensitive data.
        2. Create a `SensitiveComponent` with field `data_object: SensitiveData = None` and fetch a `SensitiveData` instance in `mount`.
        3. Create a template with `<input type="text" unicorn:model="data_object.public_field">`.
        4. Create a Django view to render the template with `SensitiveComponent`.
        5. Access the page, view HTML source.
        6. Find `<script type="application/json" id="unicorn:data:sensitivecomponent-...">` and verify it contains the full `SensitiveData` object including `secret_field_1` and `secret_field_2`.

### 6. Remote Code Execution (RCE) via Deserialization of Cached Components

- **Vulnerability Name:** Remote Code Execution (RCE) via Deserialization of Cached Components
- **Description:**
    - Django-unicorn uses `pickle` to serialize and cache component state. Deserializing maliciously crafted pickled data from the cache can lead to Remote Code Execution.
    - **Step-by-step trigger:**
        1. An attacker gains the ability to write to the Django cache backend (through exploits or misconfiguration).
        2. The attacker injects malicious pickled data into the cache, targeting a component's cache key.
        3. When the application attempts to restore the component from the cache, `pickle.loads` deserializes the malicious payload.
        4. This deserialization triggers the execution of arbitrary Python code on the server.

- **Impact:**
    - **Critical**. Remote Code Execution, allowing complete server compromise, data theft, and denial of service.

- **Vulnerability Rank:** critical

- **Currently implemented mitigations:**
    - `cachetools.lru.LRUCache` and Django's cache are used.
    - Checksum verification for message requests (not effective against cache poisoning).

- **Missing mitigations:**
    - **Replace `pickle` with a safer serialization method like `orjson` or `json`.**
    - Protection against cache poisoning.
    - Input validation/sanitization on cached data (impossible with `pickle`).
    - Consider digital signatures or encryption for cached data.

- **Preconditions:**
    - Django-unicorn caching is enabled.
    - An attacker can write arbitrary data to the Django cache backend.
    - The server attempts to restore a component from the cache containing malicious pickled data.

- **Source code analysis:**
    - `django_unicorn/cacher.py` uses `pickle` for serialization and deserialization.
    - `cache_component` uses `pickle.dumps` to serialize components.
    - `restore_from_cache` uses `pickle.loads` to deserialize components - **Vulnerable function**.

        ```python
        # File: django_unicorn/cacher.py
        import pickle # Unsafe serialization library
        ...
        def restore_from_cache(component_cache_key):
            """
            Restores the component from the Django cache backend.
            """
            pickled_component = cache.get(component_cache_key, None, cache_alias=get_cache_alias())

            if pickled_component:
                try:
                    component = pickle.loads(pickled_component) # Deserialization with pickle - CRITICAL VULNERABILITY
                    ...
                    return component
                except Exception as e:
                    logger.error(...)
                    return None
            return None
        ```

- **Security test case:**
    - **Vulnerability Test Name:** RCE via Pickle Deserialization
    - **Test Description:** Inject malicious pickled payload into cache and trigger component restoration to achieve RCE.
    - **Step-by-step test:**
        1. **Vulnerable Cache Setup (Simulated Poisoning):** Use Django's cache API to insert a malicious payload.
        2. **Craft Malicious Payload:** Create a Python script to generate a malicious pickled payload:
        ```python
        import os
        import pickle

        class MaliciousComponent:
            def __reduce__(self):
                return (os.system, ('touch /tmp/unicorn_rce_poc',))

        malicious_component = MaliciousComponent()
        pickled_payload = pickle.dumps(malicious_component)

        with open("malicious_payload.pickle", "wb") as f:
            f.write(pickled_payload)
        ```
        3. **Inject Payload into Cache:** Use Django's cache API to set a cache entry with a key used by django-unicorn (e.g., "unicorn:component:test_rce_component") and the malicious payload.
        ```python
        from django.core.cache import cache
        with open("malicious_payload.pickle", "rb") as f:
            malicious_payload = f.read()

        cache_key = "unicorn:component:test_rce_component"
        cache.set(cache_key, malicious_payload)
        ```
        4. **Trigger Component Restoration:** Access a page that renders a cached component to trigger restoration.
        5. **Verify RCE:** Check if `/tmp/unicorn_rce_poc` was created on the server. If yes, RCE is confirmed.
        6. **Cleanup:** `cache.delete(cache_key)`.

### 7. Cross-Site Scripting (XSS) vulnerability due to unsafe HTML sanitization in component rendering

- **Vulnerability Name:** Cross-Site Scripting (XSS) vulnerability due to unsafe HTML sanitization in component rendering
- **Description:**
    - Django-unicorn attempts to sanitize HTML during component rendering using `sanitize_html` and `HTMLFormatter`. However, the `_desoupify` method in `UnicornTemplateResponse.render` *unescapes* HTML entities, effectively undoing the sanitization and creating a significant XSS vulnerability. This affects both initial component rendering and updates.
    - **Step-by-step trigger:**
        1. An attacker injects malicious JavaScript code into a component property.
        2. The component template renders this property using `{{ property }}`.
        3. Although `sanitize_html` might encode the data initially (for JSON part), `_desoupify` unescapes HTML entities in the main template content.
        4. The unescaped malicious JavaScript is rendered into the HTML response.
        5. The victim's browser executes the malicious JavaScript, leading to XSS.

- **Impact:**
    - High. Arbitrary JavaScript execution in the user's browser, leading to account hijacking, website defacement, malicious redirects, and data theft.

- **Vulnerability Rank:** high

- **Currently implemented mitigations:**
    - `sanitize_html` function and `HTMLFormatter` are used in `UnicornTemplateResponse.render` for JSON data in `<script>` tags, providing HTML encoding.
    - Default HTML encoding for responses (prior to version 0.36.0 behavior, but effectively negated).

- **Missing mitigations:**
    - **Remove or fix `_desoupify` to prevent HTML unescaping.**
    - `sanitize_html` only performs basic HTML encoding, which is insufficient sanitization.
    - Robust HTML sanitization using a library like `bleach` is needed.
    - Input validation and sanitization in component Python code.
    - Content Security Policy (CSP) is missing.

- **Preconditions:**
    - Application uses django-unicorn components and renders dynamic content.
    - Component property is populated with user-controlled data without sanitization in Python code.
    - Template renders this property using `{{ property }}` or similar, and the flawed `_desoupify` unescapes malicious HTML.

- **Source code analysis:**
    1. **`django_unicorn/components/unicorn_template_response.py` -> `render`**: Shows usage of `sanitize_html` for JSON data encoding and flawed `_desoupify` for HTML unescaping.
        ```python
        def render(self):
            ...
            json_tag.string = sanitize_html(init) # HTML encoding for JSON data
            ...
            rendered_template = UnicornTemplateResponse._desoupify(soup) # HTML Unescaping - VULNERABLE
            response.content = rendered_template
            ...
        ```
    2. **`django_unicorn/utils.py` -> `sanitize_html`**: Performs basic HTML encoding.
        ```python
        def sanitize_html(html: str) -> SafeText:
            """
            Escape all the HTML/XML special characters with their unicode escapes, so
            value is safe to be output in JSON.
            ...
            """
            html = html.translate(_json_script_escapes) # HTML Encoding
            return mark_safe(html)
        ```
    3. **`django_unicorn/components/unicorn_template_response.py` -> `_desoupify`**:  Actively *unescapes* HTML entities, creating the vulnerability.
        ```python
        @staticmethod
        def _desoupify(soup):
            """
            Returns prettified and unescaped string from BeautifulSoup object.
            """
            ...
            unescaped = html.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&") # HTML Unescaping - VULNERABLE
            return unescaped
        ```

- **Security test case:**
    - **Vulnerability Test Name:** XSS via `_desoupify` Unescaping
    - **Test Description:** Inject malicious JavaScript and demonstrate XSS due to flawed HTML unescaping in `_desoupify`.
    - **Step-by-step test:**
        1. Create a django-unicorn component with property `unsafe_data`.
        2. In template, render `{{ unsafe_data }}` within a `<div>`.
        ```html
        <div>{{ unsafe_data }}</div>
        ```
        3. In `urls.py`, render the component directly as a view, passing a malicious payload as `unsafe_data`:
        ```python
        from django.urls import path
        from django_unicorn.components import UnicornView

        class XssTestComponent(UnicornView):
            template_name = "templates/test_component.html"
            unsafe_data = ""

        urlpatterns = [
            path("xss-test/", XssTestComponent.as_view(unsafe_data='<img src=x onerror=alert("XSS")>')),
        ]
        ```
        4. Access `/xss-test/` in a browser.
        5. Verify if `alert('XSS')` executes, confirming XSS.
        6. Test with various XSS vectors to assess vulnerability extent.

### 8. Potential Cross-Site Scripting (XSS) vulnerability via component attributes during direct view rendering

- **Vulnerability Name:** Potential Cross-Site Scripting (XSS) vulnerability via component attributes during direct view rendering
- **Description:**
    - When rendering components as direct views using `Component.as_view()`, component attributes might not be consistently sanitized, leading to XSS. Although `sanitize_html` is used for initial JSON data, the flawed `_desoupify` could negate this protection, especially for attributes passed through `as_view` kwargs or component properties.
    - **Step-by-step trigger:**
        1. Render a django-unicorn component directly as a view using `Component.as_view()`.
        2. Pass user-controlled data as kwargs to `as_view()`, setting component attributes.
        3. The template renders these attributes using `{{ attribute }}`.
        4. Due to `_desoupify`, the HTML entities might be unescaped.
        5. If malicious JavaScript is present in the attributes, it executes in the user's browser, causing XSS.

- **Impact:**
    - High. Similar XSS impact as vulnerability 7: arbitrary JavaScript execution, account hijacking, website defacement, etc.

- **Vulnerability Rank:** high

- **Currently implemented mitigations:**
    - `sanitize_html` for initial JSON data.
    - Default HTML encoding (but likely negated by `_desoupify`).

- **Missing mitigations:**
    - Consistent and effective HTML sanitization for component attributes in direct views, addressing the flawed `_desoupify`.
    - Robust sanitization library like `bleach`.
    - Content Security Policy (CSP).

- **Preconditions:**
    - Django-unicorn component rendered as a direct view using `Component.as_view()`.
    - User-controlled data in component attributes via `as_view` kwargs or properties.
    - Template renders these attributes allowing JavaScript execution if unsanitized.

- **Source code analysis:**
    - **`django_unicorn/components/unicorn_view.py` -> `dispatch`**: Calls `render_to_response` with `init_js=True`.
        ```python
        def dispatch(self, request, *args, **kwargs):  # noqa: ARG002
            """
            Called by the `as_view` class method when utilizing a component directly as a view.
            """
            ...
            return self.render_to_response(
                context=self.get_context_data(),
                component=self,
                init_js=True, # Triggers Javascript initialization
            )
        ```
    - `render_to_response` uses `UnicornTemplateResponse.render`.
    - Based on vulnerability 7's analysis, `_desoupify` likely makes direct views vulnerable as well.

- **Security test case:**
    - **Vulnerability Test Name:** Direct View XSS
    - **Test Description:** Demonstrate XSS vulnerability in direct view rendering by injecting malicious payload via `as_view` kwargs.
    - **Step-by-step test:**
        1. Create a django-unicorn component `DirectViewXssComponent` with property `direct_view_data`. Use the same template as vulnerability 7.
        ```html
        <div>{{ unsafe_data }}</div>  {# Assuming template file is templates/test_component.html #}
        ```
        2. In `urls.py`, render `DirectViewXssComponent` as direct view using `Component.as_view()`, passing malicious payload as `direct_view_data` kwarg:
        ```python
        from django.urls import path
        from django_unicorn.components import UnicornView

        class DirectViewXssComponent(UnicornView):
            template_name = "templates/test_component.html"
            direct_view_data = ""


        urlpatterns = [
            path("direct-view-xss/", DirectViewXssComponent.as_view(direct_view_data='<img src=x onerror=alert("Direct View XSS")>')),
        ]
        ```
        3. Access `/direct-view-xss/` in browser.
        4. Verify if `alert('Direct View XSS')` executes (XSS confirmed).
        5. Test with different XSS vectors.
        6. Inspect HTML source for unsanitized payload.
