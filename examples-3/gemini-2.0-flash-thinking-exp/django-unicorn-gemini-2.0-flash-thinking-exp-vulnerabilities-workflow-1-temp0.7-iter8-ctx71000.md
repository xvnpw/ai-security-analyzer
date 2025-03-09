## Combined Vulnerability List

This document consolidates a list of identified vulnerabilities, removing duplicates and categorizing them for clarity.

### 1. Insecure Method Invocation

* Description:
    1. An attacker can craft a malicious request to the Django Unicorn backend.
    2. This request can specify an arbitrary method name to be invoked on the `UnicornView` instance.
    3. The `django-unicorn` framework, without sufficient validation, uses `getattr` to retrieve and execute the method specified in the request payload.
    4. By manipulating the method name in the request, an attacker can potentially invoke any public method of the `UnicornView` class, regardless of the developer's intended actions.
    5. This can lead to unintended functionality execution, data manipulation, or information disclosure depending on the available methods in the `UnicornView` and the application logic.

* Impact:
    - **High**: An attacker can invoke arbitrary methods on the backend component. This can bypass intended application logic, potentially leading to data modification, unauthorized actions, or information disclosure. The exact impact depends on the specific methods available in the `UnicornView` and how they are implemented. In the worst case, if a `UnicornView` has methods that interact with sensitive data or perform critical operations without proper authorization checks, this vulnerability could be critical.
* Vulnerability Rank: high
* Currently Implemented Mitigations:
    - None. The code directly uses `getattr` with the method name provided from the client-side request without any explicit validation or sanitization of the method name against a whitelist of allowed methods.
* Missing Mitigations:
    - **Whitelist of allowed methods:** Implement a strict whitelist of methods that can be invoked from the frontend. The framework should only allow execution of methods explicitly defined as safe and intended to be called from the client side.
    - **Input validation and sanitization:** Validate and sanitize the method name received from the client to ensure it conforms to expected patterns and does not contain malicious characters or payloads.
* Preconditions:
    - The application must be using Django Unicorn framework.
    - The application must have `UnicornView` components with public methods that are not intended to be invoked directly by external users.
    - The attacker needs to be able to send AJAX requests to the Django Unicorn endpoint.
* Source Code Analysis:
    1. **File:** `django_unicorn/views.py`
    2. **Method:** `handle_action(self, request)`
    3. **Code Snippet:**
    ```python
    def handle_action(self, request):
        ...
        action_name = data.get("action_name")
        ...
        method, args, kwargs = parse_call_method_name(action_name)
        ...
        try:
            if hasattr(self, method):
                component_method = getattr(self, method) # Vulnerable line
                ...
                return_value = component_method(*args, **kwargs)
        ...
    ```
    4. **Vulnerability Flow:**
        - The `handle_action` method retrieves the `action_name` from the request `data`. This `action_name` is directly controlled by the client.
        - `parse_call_method_name` parses the `action_name` string to extract the method name, arguments, and keyword arguments.
        - `getattr(self, method)` retrieves a method from the `UnicornView` instance using the `method` name parsed from the client request. **This is the vulnerable point.** There is no check to ensure that the `method` is a safe or intended method to be called from the frontend.
        - `component_method(*args, **kwargs)` then executes the retrieved method.
    5. **Visualization:**
    ```
    Client Request (action_name: "malicious_method") --> handle_action()
                                                                |
                                        parse_call_method_name() --> method = "malicious_method"
                                                                |
                                                getattr(self, method) --> Retrieves self.malicious_method (if exists)
                                                                |
                                        component_method(*args, **kwargs) --> Executes self.malicious_method()
    ```

* Security Test Case:
    1. **Pre-requisite:** Set up a Django project with django-unicorn installed and a simple Unicorn component with at least two methods: one intended to be called from the template (e.g., `increment_count`) and another one that is not intended to be directly accessible from the template, but is still public (e.g., `delete_all_users` - for demonstration purposes, this method should ideally not actually delete users in a real test, but rather perform a harmless action to prove method invocation).
    2. **Component Code Example (`test_component.py`):**
    ```python
    from django_unicorn.components import UnicornView

    class TestComponentView(UnicornView):
        count = 0

        def increment_count(self):
            self.count += 1

        def unsafe_method(self):
            self.count = 999 # Harmless action for demonstration, in real scenario could be dangerous
    ```
    3. **Template Code Example (`test_component.html`):**
    ```html
    {% load unicorn %}
    <div>
        Count: {{ count }}
        <button unicorn:click="increment_count">Increment</button>
    </div>
    ```
    4. **Test Steps:**
        a. Render the template containing the `test_component`. Observe the initial count value (0).
        b. Click the "Increment" button. Verify that `increment_count` method is correctly called and the count increases.
        c. Open browser's developer tools and inspect the AJAX request sent when clicking "Increment" button. Note the structure of the request payload, particularly the `"action_name"` parameter.
        d. Manually craft a new AJAX POST request to the Django Unicorn endpoint (`/unicorn/message/test-component`) using tools like `curl`, `Postman` or browser's developer console.
        e. In the crafted request payload, modify the `"action_name"` parameter to call the unintended method, e.g., `"action_name": "unsafe_method"`. Keep other necessary parameters like `component_id`, `checksum`, and `data` consistent with a valid request.
        f. Send the crafted request.
        g. After sending the request, re-render or refresh the component (e.g., by clicking "Increment" again or refreshing the page).
        h. **Verification:** Observe the `count` value. If the `unsafe_method` was successfully invoked, the count value should be changed to 999 (or whatever action `unsafe_method` performs). This confirms the Insecure Method Invocation vulnerability.

* Missing Mitigations:
    - Input validation and sanitization for `action_name`.
    - Implementation of a whitelist for allowed methods.

This vulnerability allows an attacker to bypass the intended interaction flow of the component and directly trigger backend methods, potentially leading to significant security risks. It is crucial to implement mitigations, especially a method whitelist, to restrict the callable methods to only those explicitly intended for frontend interaction.

### 2. Cross-Site Scripting (XSS) Vulnerabilities

This category encompasses several related Cross-Site Scripting vulnerabilities arising from different contexts within the Django Unicorn framework.

#### 2.1. Reflected XSS via Component Method Arguments

* Description:
    An attacker can trigger a reflected Cross-Site Scripting (XSS) vulnerability by injecting malicious Javascript code as arguments to component methods called using `Unicorn.call()`. When these arguments are rendered in the component's template without proper HTML encoding, the injected script can be executed in the victim's browser. This vulnerability arises because while Django Unicorn implements HTML encoding for component fields updated via `unicorn:model`, it does not enforce consistent HTML encoding for arguments passed directly to Javascript functions through `Unicorn.call()` when these arguments are subsequently rendered in the component template.

    **Step-by-step trigger:**
    1. An attacker crafts a URL or manipulates the application state to allow execution of Javascript code in the browser's console.
    2. The attacker uses the browser's developer console to execute Javascript code that calls a Django Unicorn component method using `Unicorn.call()`.
    3. The attacker includes a malicious Javascript payload as one of the arguments passed to `Unicorn.call()`.
    4. The Django Unicorn backend receives the message, processes the `callMethod` action, and invokes the specified component method, passing the attacker-controlled Javascript payload as an argument.
    5. The component method logic or the template rendering process incorporates the argument into the HTML output without sufficient HTML encoding.
    6. The server sends the re-rendered component HTML back to the client.
    7. The browser renders the updated component, and because the malicious Javascript payload was not properly encoded, it is executed by the browser, resulting in XSS.

* Impact:
    - **High**: Successful exploitation of this vulnerability allows an attacker to execute arbitrary Javascript code in the victim's browser within the security context of the vulnerable web application. This can lead to session hijacking, account takeover, defacement, redirection to malicious sites, and information theft.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - HTML encoding for field values updated through `unicorn:model`.
    - Mechanisms for developers to bypass HTML encoding using `safe` meta attribute and template filter.

* Missing Mitigations:
    - Consistent HTML encoding for `Unicorn.call()` arguments when rendered in the component template.

* Preconditions:
    1. Django Unicorn is used in the web application.
    2. Components are integrated into web pages.
    3. At least one component method can be invoked from the frontend using `Unicorn.call()`.
    4. The component's template renders data influenced by arguments passed to methods called via `Unicorn.call()`.
    5. The component template does not explicitly HTML-encode these arguments.

* Source Code Analysis:
    1. `django_unicorn/views.py`: Handles Unicorn requests.
    2. `django_unicorn/views/__init__.py`: Processes component requests, including action handling and rendering.
    3. `django_unicorn/views/action_parsers/call_method.py`: Parses and handles `callMethod` actions, invoking component methods with arguments.
    4. `django_unicorn/components/unicorn_view.py`: Renders components using `UnicornTemplateResponse`.
    5. `django_unicorn/components/unicorn_template_response.py`: Renders templates and updates HTML, uses `sanitize_html` for JSON data in script tags but not for general template rendering of method arguments.
    6. `django_unicorn/templatetags/unicorn.py`: Renders components, passing the component instance to the template context.

* Security Test Case:
    1. Create a component `call_arg_xss_test` with a method `receive_and_render(self, arg)` that stores `arg` in `self.render_arg`.
    2. Template `call_arg_xss_test.html` renders `{{ render_arg }}` without escaping.
    3. Include the component in a Django template.
    4. Access the view in a browser and open the developer console.
    5. Execute `Unicorn.call('call_arg_xss_test', 'receive_and_render', '<img src=x onerror=alert("XSS_via_call_arg")>')`.
    6. Verify if an alert box "XSS_via_call_arg" appears, confirming XSS.
    7. Inspect the HTML source to confirm the malicious payload is rendered without encoding.

#### 2.2. XSS via Unsafe HTML Attributes in Templates

* Description:
    An attacker can inject arbitrary HTML attributes into DOM elements managed by Django Unicorn. This is possible because the `dumps` function in `django_unicorn\serializer.py` does not properly sanitize attribute keys when serializing component data, allowing an attacker to insert malicious attributes through component properties. When these properties are used in templates within HTML attributes (e.g., using `unicorn:attr:` or similar mechanisms), the injected attributes are rendered without proper escaping, leading to XSS.

    **Steps to trigger vulnerability:**
    1. Create a Django Unicorn component with a property that can be controlled by an attacker.
    2. In the component's view, set this property to a string containing a malicious HTML attribute injection payload (e.g., `"><img src=x onerror=alert(document.domain)>`).
    3. In the component's template, use this property to dynamically set an HTML attribute (e.g., hypothetical `unicorn:attr:data-custom-attribute="component_property"` or direct template rendering into attributes).
    4. When the component is rendered or updated, the malicious attribute is injected into the HTML, and the injected JavaScript code executes, leading to XSS.

* Impact:
    - **High**: Cross-site scripting (XSS). An attacker can execute arbitrary JavaScript code in the victim's browser, leading to session hijacking, cookie theft, redirection to malicious websites, or defacement.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - Django Unicorn HTML encodes updated field values by default for HTML content.

* Missing Mitigations:
    - Input sanitization for HTML attribute keys during serialization in `dumps` function within `django_unicorn\serializer.py`.
    - Context-aware output encoding when rendering HTML attributes from component properties in templates.

* Preconditions:
    1. Django Unicorn application is deployed and publicly accessible.
    2. The application uses a component that renders HTML attributes based on component properties influenced by user input.

* Source Code Analysis:
    1. **File:** `django_unicorn/serializer.py`
    2. **Function:** `dumps(data, *, fix_floats=True, exclude_field_attributes=None, sort_dict=True)`
    3. **Analysis:** The `dumps` function serializes data to JSON without sanitizing dictionary keys, which can become HTML attribute names.

* Security Test Case:
    1. Create a component `xss_attribute_component`.
    2. Component View (`myapp/components/xss_attribute_component.py`): Set `malicious_attribute = '"><img src=x onerror=alert(document.domain)>'` in `mount()`.
    3. Component Template (`myapp/templates/unicorn/xss_attribute_component.html`): `<div id="test-element" data-attribute="{{ malicious_attribute }}">Test</div>` and JavaScript to set `data-malicious` from `data-attribute`.
    4. Include component in a Django template.
    5. Create a Django view and URL.
    6. Run the Django development server.
    7. Access the page in a browser.
    8. Verify XSS: Observe if `alert(document.domain)` executes, confirming XSS due to unsanitized attribute.

#### 2.3. Potential XSS through Misuse of "safe" Template Feature

* Description:
    Django-unicorn components are rendered using Django templates, which by default automatically escape HTML to prevent XSS. However, django-unicorn provides developers with the ability to bypass this auto-escaping through Django's "safe" template filter and a `safe` Meta option in components. If a developer uses these features to render untrusted user-provided data without proper sanitization, it can lead to a Cross-Site Scripting (XSS) vulnerability. An attacker can inject malicious JavaScript code as user input, and if this input is rendered using `safe`, the script will execute.

* Impact:
    - **High**: XSS attack allows arbitrary JavaScript execution, potentially leading to session hijacking, cookie theft, redirection, website defacement, and data theft.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    - Django's Default HTML Escaping.
    - Documentation of `safe` feature.
    - Security Fix for CVE-2021-42053 (HTML encoding in responses).

* Missing Mitigations:
    - Stronger Warnings in Documentation about `safe` misuse.
    - Best Practices for Sanitization when using `safe`.
    - Security Test Cases for `safe` Misuse.

* Preconditions:
    1. Usage of django-unicorn Components.
    2. Rendering User-Provided Data in templates.
    3. Misuse of `safe` mechanism (filter or Meta option) for user data.
    4. Attacker Data Injection into rendered data.

* Source Code Analysis:
    - Django-unicorn leverages Django's template engine with default auto-escaping.
    - Vulnerability arises from *intended* use of `safe` features to bypass auto-escaping.
    - `django_unicorn/utils.py`: `sanitize_html` for JSON serialization, not general template sanitization.
    - `django_unicorn/components/unicorn_template_response.py`: Standard Django template rendering.
    - `django_unicorn/views/__init__.py`: Handles `safe_fields` from `Meta.safe`, using `mark_safe` to disable escaping for specified fields.
    - Tests in `django-unicorn/tests/views/test_process_component_request.py` demonstrate non-encoding behavior of `safe` Meta option.

* Security Test Case:
    1. Create a component `XssComponent` with `safe = ("user_message",)` in Meta and property `user_message`.
    2. Template renders `{{ user_message }}`.
    3. Create a view to render `XssComponent`.
    4. Craft a malicious URL to pass XSS payload as `user_message`.
    5. Access URL and verify XSS execution (`alert("XSS Vulnerability")`).
    6. Mitigate by removing `safe = ("user_message",)` and re-test to verify XSS is prevented by auto-escaping.

### 3. Potential Path Traversal in Component Name

* Description:
    The `component_name` parameter in the `/unicorn/message/<component_name>` URL is used to dynamically load component classes. The regex `[\w/\.-]+` allows forward slashes and dots. While slashes are replaced with dots, a crafted `component_name` could lead to attempts to import modules from unexpected locations, potentially causing information disclosure or unexpected behavior.

* Impact:
    - **High**: Potential information disclosure if module loading is manipulated to expose internal application structure or code. Unexpected application behavior if module loading fails.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - Django's URL routing with regex to limit `component_name` characters.
    - `get_locations` function replaces `/` with `.` in `component_name`.
    - Django's module import system provides some protection.

* Missing Mitigations:
    - Input validation for `component_name` to prevent path traversal attempts.
    - Restricting allowed characters in `component_name` regex.
    - Further investigation to confirm exploitability.

* Preconditions:
    - Application is running and accessible.
    - Attacker identifies `/unicorn/message` endpoint.

* Source Code Analysis:
    - **urls.py:** `re_path(r"message/(?P<component_name>[\w/\.-]+)", views.message, name="message")` - Regex allows `/` and `.`.
    - **components/unicorn_view.py:** `get_locations(component_name)` replaces `/` with `.`.
    - **components/unicorn_view.py:** `_get_component_class` uses `importlib.import_module`.

* Security Test Case:
    1. Prepare Django Unicorn project.
    2. Craft malicious URL: `/unicorn/message/../../../example/www/views`.
    3. Send POST request with valid JSON payload to crafted URL using `curl`.
    4. Analyze response for module loading errors (`ModuleNotFoundError`, `ImportError`).
    5. Check server logs for attempted module import details.
    6. Refine test with variations like `..\/..\/evil_component`, `components/../../evil_component`.

### 4. Potential Code Injection via Argument Parsing in `parse_call_method_name`

* Description:
    The `parse_call_method_name` function uses `ast.parse` and `ast.literal_eval` to parse method arguments from a string received from the frontend. Malicious users might inject code or unexpected values through crafted arguments in `call_method_name`, leading to unintended behavior.

    **Steps to trigger vulnerability:**
    1. Attacker crafts a request to Django Unicorn backend.
    2. Attacker modifies `call_method_name` parameter to include malicious payload in method arguments.
    3. Django Unicorn backend calls `parse_call_method_name` to parse arguments.
    4. If sanitization is insufficient, `ast.literal_eval` might process the malicious payload.

* Impact:
    - **High**: Potential data manipulation, information disclosure, SSRF, DoS. In severe cases, potential RCE.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - Uses `ast.literal_eval` for parsing arguments, safer than `eval`.

* Missing Mitigations:
    - Robust input sanitization and validation for `call_method_name` before parsing.
    - Strict format enforcement for method names and arguments.
    - Regular expression or parsing validation of `call_method_name`.
    - Rejection of invalid `call_method_name` requests.
    - Security review of frontend `call_method_name` construction to prevent injection points.

* Preconditions:
    - Django Unicorn components with methods called from frontend.
    - Attacker can manipulate `call_method_name` parameter in AJAX request.

* Source Code Analysis:
    - File: `django_unicorn/call_method_parser.py`, Function: `parse_call_method_name(call_method_name: str)` uses `ast.parse` and `ast.literal_eval`.
    - File: `django_unicorn/views/action_parsers/call_method.py`, Function: `handle` calls `parse_call_method_name` and then calls component method with parsed arguments.

* Security Test Case:
    1. Setup Test Component: `TestComponentView` with `test_method(self, arg1)` that prints `arg1`.
    2. Craft Malicious Payload: `call_method_name`: `"test_method(1+1)"` or `"test_method(__import__('os').system('echo VULNERABILITY_DEMO'))"`.
    3. Send Crafted Request: POST request to `/unicorn/message` with crafted payload in `action_queue[0].payload.name`.
    4. Observe Server Behavior: Monitor server logs for code execution or errors related to argument parsing.
    5. Refine Test: Test with large strings, complex data structures, type confusion attempts to check for unintended behavior.

### 5. Cross-Site Scripting (XSS) via Unsafe HTML Attributes in Templates (Revisited)

* Description:
    1. An attacker crafts a malicious string containing Javascript code.
    2. This malicious string is injected into a component's property, either directly or indirectly via user input.
    3. The `set_property_from_data` function updates the component's property.
    4. The component template uses this property to render HTML attributes without proper attribute-specific sanitization.
    5. When rendered, the malicious Javascript code in the HTML attribute is executed in the victim's browser, leading to XSS.

* Impact:
    - **Critical**: XSS can lead to account takeover, session hijacking, sensitive data theft, redirection, and defacement.

* Vulnerability Rank: critical

* Currently Implemented Mitigations:
    - HTML encoding of component data in responses (likely for HTML content, not attributes).
    - `sanitize_html` for JSON data within `<script>` tag in `UnicornTemplateResponse.render`.
    - Django's built-in template escaping (may be insufficient for attributes).

* Missing Mitigations:
    - **Context-Aware Output Encoding for HTML Attributes:** Attribute-specific encoding for dynamically rendered content in HTML attributes.
    - **Input Sanitization in `set_property_from_data`:** Sanitize user-provided data in `set_property_from_data` before updating component properties.
    - **Content Security Policy (CSP):** Implement strict CSP as defense-in-depth.
    - **Regular Security Audits and Testing:** Focus on XSS in component templates and data handling.

* Preconditions:
    - Component template dynamically renders user-controlled data into HTML attributes *without attribute-specific encoding*.
    - Attacker can influence the data rendered into attributes.

* Source Code Analysis:
    - **Template Rendering:** Django templates with potential insufficient auto-escaping for attributes.
    - **`set_property_from_data`:** Updates properties without sanitization (tested in `test_set_property_from_data.py`).
    - **`safe` Meta Option and `sanitize_html`:** `safe` option bypasses encoding. `sanitize_html` for JSON in `<script>`, not general attribute encoding.
    - **`UnicornTemplateResponse.render`:** Renders component, `sanitize_html` for init data, but no attribute encoding enforced in template rendering.

* Security Test Case:
    1. Create `AttributeXSSView` component with `unsafe_attribute` property.
    2. Template: `<button data-attribute="{{ unsafe_attribute }}">Click Me</button>`.
    3. Access `/attribute-xss` and render the component.
    4. In browser console, execute `Unicorn.getComponent('attribute-xss').set({'unsafe_attribute': '"><img src=x onerror=alert(\'XSS\')>'});`.
    5. Click "Click Me" button.
    6. Verify if `alert('XSS')` executes, confirming XSS in `data-attribute`.
    7. Test with other attributes like `href`, `src` and payloads like `"javascript:alert('XSS')"`.
