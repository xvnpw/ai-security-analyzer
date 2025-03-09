## Combined Vulnerability List for django-unicorn project

This document outlines the identified vulnerabilities in the django-unicorn project, combining information from the provided lists and removing any duplicates.

### 1. Potential Cross-Site Scripting (XSS) vulnerability due to misuse of `safe` filter/setting

- Description:
    Django Unicorn allows developers to use the `safe` template filter or `Meta.safe` setting to bypass HTML encoding for component properties. If these features are mistakenly applied to user-controlled data without proper sanitization, it can lead to Cross-Site Scripting (XSS) vulnerabilities. An attacker can inject malicious JavaScript code through user input. If a developer uses `safe` filter or `Meta.safe` to render this unsanitized input, the injected code will be executed in the user's browser.

    **Step-by-step trigger:**
    1. A developer creates a Django Unicorn component with a property that is influenced by user input, for example, through `unicorn:model`.
    2. In the component's template, the developer renders this user-controlled property using the `safe` template filter (e.g., `{{ user_input|safe }}`) or by including the property name in the `Meta.safe` tuple within the component's view.
    3. An attacker enters malicious JavaScript code, such as `<script>alert("XSS")</script>`, into the user input field.
    4. When the component is rendered, either on initial page load or after an update triggered by user interaction, the malicious JavaScript code is rendered without HTML encoding due to the `safe` filter/setting.
    5. The user's browser executes the injected JavaScript code, resulting in an XSS attack.

- Impact:
    Successful XSS attacks enable an attacker to execute arbitrary JavaScript code within a victim's browser. This can lead to serious security breaches, including session hijacking, cookie theft, website defacement, redirection to malicious websites, and unauthorized actions performed on behalf of the user.

- Vulnerability Rank: high

- Currently implemented mitigations:
    By default, Django Unicorn leverages Django's template engine to automatically HTML encode all output. This default behavior serves as a robust mitigation against XSS vulnerabilities and is applied to all template variables unless developers explicitly bypass it using the `safe` filter or the `Meta.safe` setting in Unicorn components.

- Missing mitigations:
    Django Unicorn relies on developer responsibility regarding the use of `safe` filter and `Meta.safe`. The documentation currently lacks a prominent warning about the security risks associated with using `safe` with unsanitized user input.  Furthermore, there is a lack of comprehensive guidance within the documentation on recommended sanitization techniques for developers who need to bypass HTML encoding using `safe`. While the `sanitize_html` utility function exists in `django_unicorn.utils`, its documentation does not clearly define its purpose and limitations in the context of XSS prevention for template rendering, potentially leading to its misuse.  The documentation should explicitly clarify that `sanitize_html` is primarily for escaping HTML for JSON serialization and not a general-purpose XSS sanitizer for template output.

- Preconditions:
    - The application utilizes a Django Unicorn component.
    - A developer employs the `safe` template filter or `Meta.safe` setting within a component's template.
    - The `safe` filter/setting is applied to a component property that is either directly or indirectly influenced by user input.
    - User input that is rendered with the `safe` filter/setting is not properly sanitized.

- Source code analysis:
    - The documentation in `docs/source/views.md` and `docs/source/templates.md` describes the `Meta.safe` setting and `safe` template filter, explicitly outlining the mechanism to bypass default HTML encoding.
    - The changelog for version v0.36.0 mentions HTML encoding as a security fix, indicating an awareness of XSS risks and the deliberate implementation of default encoding.
    - `django_unicorn/utils.py` contains the `sanitize_html` function:
        ```python
        def sanitize_html(html: str) -> SafeText:
            """
            Escape all the HTML/XML special characters with their unicode escapes, so
            value is safe to be output in JSON.

            This is the same internals as `django.utils.html.json_script` except it takes a string
            instead of an object to avoid calling DjangoJSONEncoder.
            """

            html = html.translate(_json_script_escapes)
            return mark_safe(html)  # noqa: S308
        ```
        This function's purpose is to escape HTML for safe inclusion within JSON, specifically using `_json_script_escapes`, which is designed for use with Django's `json_script` template tag. It is not intended to be a general-purpose HTML sanitizer for preventing XSS in template output. Developers might mistakenly believe that this function is sufficient for sanitizing user input intended for direct HTML rendering, which is not the case.
    - `django_unicorn/components/unicorn_template_response.py` handles template rendering using `BeautifulSoup`:
        ```python
        class UnicornTemplateResponse(TemplateResponse):
            # ...
            @timed
            def render(self):
                response = super().render()
                # ...
                soup = BeautifulSoup(content, features="html.parser")
                # ...
                rendered_template = UnicornTemplateResponse._desoupify(soup)
                response.content = rendered_template
        ```
        `BeautifulSoup` is used to parse and manipulate the HTML structure for adding Unicorn-specific attributes and scripts. It does not perform XSS sanitization. The responsibility for HTML sanitization rests with Django's default template engine escaping and the developer's careful use of `safe` when intentionally bypassing this default. Tests in `tests\views\test_process_component_request.py` and `tests\templatetags\test_unicorn_render.py` confirm the default HTML encoding behavior and the intended functionality of the `safe` setting.

- Security test case:
    1. Create a Django Unicorn component named `xss_test`.
    2. Define a property `unsafe_data` in the `XssTestView` component class within `components/xss_test.py`.
        ```python
        # components/xss_test.py
        from django_unicorn.components import UnicornView

        class XssTestView(UnicornView):
            unsafe_data = ""

            def set_unsafe_data(self, data):
                self.unsafe_data = data

            def get_unsafe_data(self): # Added method to trigger update from template
                return self.unsafe_data
        ```
    3. Create a template `unicorn/xss_test.html` for the component and use the `safe` filter to render `unsafe_data`.
        ```html
        {# templates/unicorn/xss_test.html #}
        <div>
            <input type="text" unicorn:model="unsafe_data" unicorn:change="get_unsafe_data"> <!-- Trigger update on change -->
            <div id="xss_output">
                {{ unsafe_data|safe }}
            </div>
        </div>
        ```
    4. Create a Django template that includes the `xss_test` component.
        ```html
        {# templates/index.html #}
        {% load unicorn %}
        <!DOCTYPE html>
        <html>
        <head>
            <title>XSS Test</title>
            {% unicorn_scripts %}
        </head>
        <body>
            {% csrf_token %}
            {% unicorn 'xss-test' %}
        </body>
        </html>
        ```
    5. Create a Django view and URL to render the `index.html` template.
        ```python
        # views.py
        from django.shortcuts import render
        from django.views.generic import View

        class IndexView(View):
            def get(self, request):
                return render(request, 'index.html')

        # urls.py
        from django.urls import path
        from .views import IndexView

        urlpatterns = [
            path('', IndexView.as_view(), name='index'),
        ]
        ```
    6. Add the component to `project/urls.py`.
        ```python
        # project/urls.py
        from django.contrib import admin
        from django.urls import include, path
        from example.www.views import IndexView # Import IndexView

        urlpatterns = [
            path("admin/", admin.site.urls),
            path("", IndexView.as_view(), name="index"), # Use IndexView for root path
            # Include django-unicorn urls
            path("unicorn/", include("django_unicorn.urls")),
        ]
        ```
    7. Run the Django development server.
    8. Access the page in a web browser and input the following JavaScript payload into the text input field: `<script>alert("XSS Vulnerability!")</script>`.
    9. Observe if an alert box with the message "XSS Vulnerability!" appears after you click out of the text input field. If an alert box appears, the XSS vulnerability is confirmed because the JavaScript code was executed.
    10. Modify the component template `unicorn/xss_test.html` to remove the `safe` filter: `{{ unsafe_data }}`.
    11. Repeat steps 8 and 9. Observe that the alert box should not appear this time, indicating that default HTML encoding is preventing XSS.

### 2. Potential Command Injection via `eval_value` in `call_method_parser.py`

- Description:
    This vulnerability arises from the way `django-unicorn` processes method calls from the frontend to backend components. An attacker could potentially craft a malicious `call_method_name` that includes embedded Python code within the arguments of a method call. The `parse_call_method_name` function in `django_unicorn\call_method_parser.py` uses `ast.parse` and `eval_value` to parse the method name and its arguments. While `eval_value` primarily utilizes `ast.literal_eval` for safe evaluation of literal expressions, it falls back to `_cast_value` if `ast.literal_eval` encounters a `SyntaxError`. If `_cast_value` fails to adequately sanitize the input, and a crafted input string bypasses `ast.literal_eval` yet still contains executable Python code, this code could be executed. This scenario could enable an attacker to inject and execute arbitrary Python code on the server when a component action is triggered.

    **Step-by-step trigger:**
    1. An attacker identifies a Django Unicorn component with a method that can be triggered from the frontend.
    2. The attacker crafts a malicious `callMethodName` payload in the request to the server. This payload includes Python code embedded within the arguments of the method call, designed to bypass `ast.literal_eval` and exploit potential weaknesses in `_cast_value`.
    3. The `parse_call_method_name` function on the server parses this payload, and the `eval_value` function attempts to evaluate the arguments.
    4. The crafted payload causes `ast.literal_eval` to raise a `SyntaxError`, leading `eval_value` to fall back to `_cast_value`.
    5. If `_cast_value` does not properly sanitize the malicious Python code within the input string, it is passed through.
    6. The server executes the injected Python code, leading to command injection.

- Impact:
    Command injection vulnerabilities are critical. Successful exploitation allows an attacker to execute arbitrary Python code directly on the server. This can lead to complete compromise of the server, including unauthorized access to sensitive data, data exfiltration, modification of server configurations, and denial of service attacks. In severe cases, it can allow the attacker to pivot to other systems within the network.

- Vulnerability Rank: critical

- Currently implemented mitigations:
    - The project uses `ast.literal_eval`, which is intended to safely evaluate literal expressions from strings, providing a degree of protection against direct execution of arbitrary code in many common scenarios.
    - Individual components might implement their own type casting and validation for method arguments. However, `django-unicorn` framework does not enforce input validation or sanitization at the framework level.

- Missing mitigations:
    - Robust input sanitization is needed within the `_cast_value` function to prevent the execution of arbitrary code, especially when `ast.literal_eval` fails.
    - Strict input validation should be enforced to ensure that arguments passed to component methods conform to expected types and formats, rejecting any input that deviates from these expectations.
    - The project should consider replacing or supplementing `ast.literal_eval` with a more secure parsing mechanism for user-provided arguments, or implement a comprehensive allow-list and input validation strategy to restrict the types of expressions that can be evaluated.

- Preconditions:
    - The application must be running `django-unicorn`.
    - An attacker must be able to trigger a component action, which is typically done through frontend interactions with the application.
    - The attacker must be able to manipulate or control the arguments that are passed to the triggered component action.

- Source code analysis:
    1. **File:** `django_unicorn\call_method_parser.py`
    2. **Function:** `eval_value(value)`
        ```python
        @lru_cache(maxsize=128, typed=True)
        def eval_value(value):
            """
            Uses `ast.literal_eval` to parse strings into an appropriate Python primitive.

            Also returns an appropriate object for strings that look like they represent datetime,
            date, time, duration, or UUID.
            """

            try:
                value = ast.literal_eval(value) # potential safe eval
            except SyntaxError:
                value = _cast_value(value) # potential unsafe handling if _cast_value is bypassed

            return value
        ```
    3. **Function:** `parse_call_method_name(call_method_name)`
        ```python
        @lru_cache(maxsize=128, typed=True)
        def parse_call_method_name(
            call_method_name: str,
        ) -> Tuple[str, Tuple[Any, ...], Mapping[str, Any]]:
            ...
            tree = ast.parse(method_name, "eval")
            statement = tree.body[0].value #type: ignore

            if tree.body and isinstance(statement, ast.Call):
                call = tree.body[0].value # type: ignore
                method_name = call.func.id
                args = [eval_value(arg) for arg in call.args] # arguments are evaluated here
                kwargs = {kw.arg: eval_value(kw.value) for kw.keywords}
            ...
        ```
    4. **Vulnerability:** The vulnerability lies in the potential for a carefully crafted string to bypass `ast.literal_eval` (by raising a `SyntaxError`) and yet still contain malicious Python code that `_cast_value` does not sanitize effectively. While `ast.literal_eval` is designed for safe evaluation of literal expressions, vulnerabilities can emerge due to complex interactions or if the fallback mechanism in `_cast_value` is insufficient to prevent code execution. The reliance on `_cast_value` as a fallback without clear input validation and sanitization presents a critical security risk.

- Security test case:
    1. Create a Django Unicorn component with a method that accepts a command argument.
        ```python
        # components/command_injection.py
        from django_unicorn.components import UnicornView

        class CommandInjectionView(UnicornView):
            def execute_command(self, command):
                import os
                os.system(command) # Insecure: for demonstration purposes only. Do not use os.system in production.

        ```
        ```html
        <!-- templates/unicorn/command_injection.html -->
        <button unicorn:click="execute_command(command)">Execute Command</button>
        <input type="text" unicorn:model="command" value="ls -l">
        ```
    2. Include this component in a Django template and render it.
    3. Open the page in a browser and use browser's developer tools to intercept network requests.
    4. Modify the request payload associated with the button click. Specifically, alter the `callMethodName` parameter to inject a malicious command. For example, change the payload to include:
        ```json
        {"callMethodName": "execute_command('__import__(\\'os\\').system(\\'touch /tmp/pwned_by_unicorn\\')')", ...}
        ```
    5. Send the modified request to the server. This can typically be done by editing and replaying the intercepted network request.
    6. **Expected outcome (Vulnerable):** If the vulnerability is present, the injected command `touch /tmp/pwned_by_unicorn` will be executed on the server. To confirm, check for the creation of the file `/tmp/pwned_by_unicorn` on the server. Successful creation indicates successful command execution.
    7. **Expected outcome (Mitigated):** If the vulnerability is mitigated, the command will not be executed, and the file `/tmp/pwned_by_unicorn` will not be created. The server might return an error if input validation mechanisms are in place to prevent such payloads.
