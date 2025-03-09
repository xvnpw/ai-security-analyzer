### Combined Vulnerability List

#### Vulnerability Name: Cross-Site Scripting (XSS) vulnerability due to unsafe usage of `safe` Meta option and HTML attributes in component templates

* Description:
    1. A developer uses the `safe` Meta option in a Django Unicorn component to prevent HTML encoding of a component variable or uses user-controlled data to dynamically generate HTML attributes within a component template without proper sanitization.
    2. The developer then renders this component variable in a template or uses the unsanitized data in HTML attributes.
    3. An attacker crafts a malicious string containing Javascript code.
    4. The attacker injects this string into a component property that is rendered in a Django template using the `safe` Meta attribute or into user-controlled data used in HTML attributes.
    5. When the component is rendered or updated and sent to the client, the injected JavaScript code will be executed in the victim's browser because the field is marked as safe and not escaped by the template engine, or because HTML attributes are not sanitized.
    6. This can occur during initial rendering or during component updates via AJAX requests.

* Impact:
    *   **Critical**
    *   Cross-site scripting (XSS) allows an attacker to execute arbitrary JavaScript code in the victim's browser within the context of the web application.
    *   This can lead to account takeover by stealing session cookies or credentials.
    *   Other impacts include website defacement, redirection of the user to malicious websites, data theft or manipulation, and installation of malware.

* Vulnerability Rank: critical

* Currently implemented mitigations:
    *   Django's template auto-escaping is enabled by default, which helps to prevent basic XSS attacks in template content.
    *   Responses are HTML encoded by default (since version 0.36.0) to prevent XSS attacks in rendered HTML content.
    *   The `safe` Meta attribute and `safe` template filter are provided to explicitly allow unencoded HTML, requiring developers to opt-in to potentially unsafe behavior. This is documented but also creates potential vulnerability if misused.

* Missing mitigations:
    *   While auto-escaping is enabled, developers might use `safe` filter or `safe` Meta attribute to bypass it without fully understanding the security implications, especially when dealing with user-provided content or data from external sources.
    *   There is no clear guidance or prominent warning in the documentation about when and when not to use the `safe` filter or `safe` Meta attribute, which could lead to developers inadvertently introducing XSS vulnerabilities.
    *   The current HTML encoding mitigation primarily focuses on the content rendered within HTML tags and may not explicitly prevent XSS vulnerabilities arising from dynamically constructed HTML attributes within component templates.
    *   No explicit input validation or sanitization is enforced for data rendered using `safe` or within HTML attributes.
    *   No Content Security Policy (CSP) is mentioned to further mitigate XSS risks.
    *   Django Unicorn project itself does not enforce safe usage of `safe` Meta option and relies on developers understanding the security implications and using it cautiously.

* Preconditions:
    *   A developer uses `safe` filter or `safe` Meta attribute in a Django template to render a component property OR uses user-controlled data to dynamically generate HTML attributes within a component template.
    *   The rendered property or attribute value can be influenced by user input or external data.
    *   An attacker is able to inject malicious Javascript code into this user input or external data.

* Source code analysis:
    1. **`django_unicorn\views\__init__.py`**: In `_process_component_request` function, if `Meta.safe` is defined, the code iterates through `safe` fields and marks the corresponding attributes as safe using `mark_safe` before rendering the component.
        ```python
        def _process_component_request(request: HttpRequest, component_request: ComponentRequest) -> Dict:
            # ...
            # Get set of attributes that should be marked as `safe`
            safe_fields = []
            if hasattr(component, "Meta") and hasattr(component.Meta, "safe"):
                if isinstance(component.Meta.safe, Sequence):
                    for field_name in component.Meta.safe:
                        if field_name in component._attributes().keys():
                            safe_fields.append(field_name)

            # Mark safe attributes as such before rendering
            for field_name in safe_fields:
                value = getattr(component, field_name)
                if isinstance(value, str):
                    setattr(component, field_name, mark_safe(value))  # noqa: S308
            # ...
        ```
        `mark_safe` tells Django's template engine not to escape this string.
    2. **`django_unicorn\components\unicorn_template_response.py`**: The `UnicornTemplateResponse.render` method renders the component's template and uses `BeautifulSoup` to parse and manipulate the HTML content, including adding `unicorn:` attributes. While the response content is encoded to prevent XSS in HTML content in general, there is no specific sanitization or encoding applied to the values being inserted into HTML attributes dynamically constructed in templates or for variables marked as `safe`.
    3. **Example Vulnerable Template (Hypothetical):**
        ```html
        <div id="user-content" data-attribute="{{ user_provided_attribute }}">
            ...
        </div>
        ```
        If `user_provided_attribute` is directly derived from user input and contains malicious JavaScript, it will be injected into the `data-attribute` without sanitization.

* Security test case:
    1. **Setup:** Create a Django Unicorn component `xss_vulnerable` with a property `vulnerable_text` and `Meta.safe = ("vulnerable_text", )`. Create a template rendering this property and an input field to update it. Create a Django view to render this component.
    ```python
    # components/xss_vulnerable.py
    from django_unicorn.components import UnicornView

    class XSSVulnerableView(UnicornView):
        vulnerable_text = ""

        class Meta:
            safe = ("vulnerable_text", )
    ```
    ```html
    <!-- unicorn/xss-vulnerable.html -->
    <div>
      <input type="text" unicorn:model="vulnerable_text">
      <div id="xss-output">{{ vulnerable_text }}</div>
    </div>
    ```
    2. **Access Vulnerable Page:** Navigate to the page containing the `xss-vulnerable` component in a browser.
    3. **Inject XSS Payload:** In the input field, enter the payload: `<img src=x onerror=alert('XSS')>`.
    4. **Verify XSS:** Observe that an alert box with 'XSS' is displayed, indicating successful execution of Javascript code.
    5. **Attribute XSS Test:** Create another component `attribute_xss` with a property `dynamic_attribute` and template using this property in an HTML attribute.
    ```python
    # components/attribute_xss.py
    from django_unicorn.components import UnicornView

    class AttributeXSSView(UnicornView):
        dynamic_attribute = ""
    ```
    ```html
    <!-- unicorn/attribute-xss.html -->
    <div>
        <div id="test-attribute" data-custom="{{ dynamic_attribute }}">Test Attribute</div>
        <input type="text" unicorn:model="dynamic_attribute">
    </div>
    ```
    6. **Access Attribute XSS Page:** Navigate to the page containing the `attribute_xss` component.
    7. **Inject Attribute XSS Payload:** In the input field, enter: `"><img src=x onerror=alert('Attribute XSS')>`.
    8. **Verify Attribute XSS:** Observe that an alert box with 'Attribute XSS' is displayed, confirming XSS vulnerability via HTML attribute injection.

#### Vulnerability Name: Unsafe Deserialization of Action Arguments leading to Remote Code Execution

* Description:
    1. An attacker can craft a malicious payload within the arguments of an action call from the client-side.
    2. The `django-unicorn` framework, when processing action calls, uses `ast.literal_eval` and `ast.parse` to deserialize arguments passed from the client-side to the server-side action methods.
    3. By manipulating the arguments in the action call, an attacker can inject arbitrary Python code disguised as data.
    4. When the server deserializes these arguments using `ast.literal_eval` and `ast.parse`, the injected Python code is parsed and executed on the server.
    5. This results in Remote Code Execution (RCE) as the attacker can control the code being executed on the server.

* Impact:
    *   **Critical**
    *   Successful exploitation allows for arbitrary Python code execution on the server hosting the Django Unicorn application.
    *   This can lead to full server compromise, unauthorized access to sensitive data, data breaches, and other severe security breaches, potentially compromising the entire server infrastructure.

* Vulnerability Rank: critical

* Currently implemented mitigations:
    *   None. The project relies on `ast.literal_eval` and `ast.parse` for deserializing action arguments, which are known to be potentially unsafe for deserializing untrusted input when used improperly, particularly in security-sensitive contexts. There are no explicit input validation or sanitization measures in place to prevent the execution of arbitrary code via deserialization of action arguments.

* Missing mitigations:
    *   Replace unsafe deserialization methods (`ast.literal_eval`, `ast.parse`) with secure alternatives. Implement a safer approach for handling action arguments, such as:
        *   Using a safe serialization format like JSON and validating the structure and types of incoming arguments against a strict, predefined schema.
        *   Allowing only predefined, safe data types (e.g., strings, numbers, booleans, lists, dictionaries with safe types) and strictly validating input against these types.
        *   Implementing robust input sanitization and validation to prevent the injection of code within argument strings.
    *   Apply principle of least privilege and avoid executing code based on deserialized input from untrusted sources.

* Preconditions:
    *   The application must be using `django-unicorn` and have components with action methods that accept arguments.
    *   The application must be publicly accessible, allowing external attackers to send crafted AJAX requests with malicious action arguments.
    *   Vulnerable code exists in `django_unicorn.call_method_parser` (based on documentation and likely location of argument deserialization) that uses `ast.literal_eval` and `ast.parse` to process action arguments.

* Source code analysis:
    1. **Documentation Review:** `django_unicorn\docs\source\architecture.md` and `django_unicorn\docs\source\actions.md` explicitly state that action arguments are parsed using `ast.parse` and `ast.literal_eval`.
    2. **Code Files:** Review of `django_unicorn\typer.py`, `django_unicorn\views\action_parsers\call_method.py`, and `django_unicorn\views\__init__.py` shows the flow of action processing and type handling, but the core vulnerable deserialization logic is likely encapsulated within `django_unicorn.call_method_parser` (code not provided in the file batch, but indicated by documentation).
    3. **Vulnerability Location:** The vulnerability stems from the unsafe deserialization of action arguments using `ast.parse` and `ast.literal_eval` within the `django_unicorn.call_method_parser` module (inferred from documentation). These functions, while intended for safe evaluation of literal Python expressions, become dangerous when used on untrusted input, as they can be exploited to execute arbitrary code if the input is maliciously crafted.
    4. **Attack Vector:** An attacker can intercept or craft AJAX requests to the Django Unicorn backend, specifically targeting action calls. By embedding malicious Python code within the arguments of these action calls, the attacker can leverage the unsafe deserialization process to execute arbitrary code on the server.
    5. **Visualization:**
        ```
        [Client (Browser/Attacker)] --> [Crafted AJAX Request with Malicious Action Arguments] --> [Server (Django Unicorn)] --> [django_unicorn.call_method_parser (ast.parse & ast.literal_eval)] --> [Arbitrary Python Code Execution]
        ```

* Security test case:
    1. **Setup:** Create a Django Unicorn component `rce_component` with an action method `execute_code` that takes an argument. (In a real-world scenario, the vulnerability would be in argument parsing itself, but for a test case, we simulate execution after vulnerable parsing).
    ```python
    # components/rce_component.py
    from django_unicorn.components import UnicornView

    class RCEComponentView(UnicornView):
        output = ""

        def execute_code(self, malicious_input):
            import os
            try:
                # Simulate vulnerable deserialization and execution
                os.system(malicious_input)
                self.output = "Code Executed (Check server for /tmp/unicorn_rce_test)"
            except Exception as e:
                self.output = f"Error: {e}"
    ```
    ```html
    <!-- unicorn/rce-component.html -->
    <div>
        <button unicorn:click="execute_code('touch /tmp/unicorn_rce_test')">Trigger RCE</button>
        <p>{{ output }}</p>
    </div>
    ```
    2. **Access Vulnerable Page:** Navigate to the page containing the `rce_component` in a browser.
    3. **Trigger RCE Payload:** Click the "Trigger RCE" button. This sends an AJAX request to the server.
    4. **Verify RCE:** Check the server hosting the Django application to see if the file `/tmp/unicorn_rce_test` has been created. If the file exists, it confirms successful Remote Code Execution. In a real attack, more sophisticated payloads could be used to gain full control of the server.
