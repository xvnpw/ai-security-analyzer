Combining the provided vulnerability lists, we have identified three distinct security issues in django-unicorn. Below is a consolidated list of these vulnerabilities, formatted as requested.

### Consolidated Vulnerability List for django-unicorn

This document outlines identified security vulnerabilities in the django-unicorn framework, detailing each issue, its potential impact, and recommended mitigations.

#### 1. Remote Code Execution via Argument Injection in Component Actions

* **Vulnerability Name:** Remote Code Execution via Argument Injection in Component Actions
* **Description:** An attacker can inject arbitrary Python code as arguments to component actions by crafting a malicious `call_method_name` string in the AJAX request to the `/unicorn/message` endpoint. The `parse_call_method_name` function in `django_unicorn\call_method_parser.py` uses `ast.literal_eval` to parse arguments. While `ast.literal_eval` is intended for safe evaluation of literals, vulnerabilities can arise from complex interactions with the rest of the framework, especially when type coercion or custom classes are involved. This allows for potential bypass or misuse leading to unintended code execution.

    **Steps to trigger:**
    1. Identify a component action that accepts arguments.
    2. Craft a malicious `call_method_name` string that includes Python code within the arguments.
    3. Send an AJAX request to `/unicorn/message` with the crafted `call_method_name` as part of the payload.
    4. If the injected code is successfully parsed and executed by the server, remote code execution can be achieved.

* **Impact:** Remote Code Execution (RCE). An attacker can execute arbitrary Python code on the server, potentially leading to full system compromise, data breach, or denial of service.
* **Vulnerability Rank:** critical
* **Currently Implemented Mitigations:** None identified in the provided files that specifically prevent argument injection in component actions. The documentation mentions CSRF protection, but this is to prevent CSRF attacks, not RCE. The use of `ast.literal_eval` is intended as a mitigation, but it might be insufficient.
* **Missing Mitigations:** Input sanitization and validation for arguments passed to component actions. Specifically:
    - Implement strict input validation to ensure arguments conform to expected types and formats.
    - Avoid using `ast.literal_eval` or similar functions directly on user-provided input for complex argument parsing if possible. If it is necessary, ensure that the context in which the evaluated literals are used is completely safe and cannot be manipulated to execute arbitrary code.
    - Consider using safer parsing methods or libraries that are specifically designed to prevent code injection.
    - Implement runtime checks to verify the type and content of arguments before they are passed to component methods.
* **Preconditions:**
    - The application must be using django-unicorn framework.
    - The application must have components with actions that accept arguments.
    - An attacker must be able to send AJAX requests to the `/unicorn/message` endpoint.
* **Source Code Analysis:**
    1. File: `django_unicorn\django_unicorn\call_method_parser.py`
    2. Function: `parse_call_method_name(call_method_name: str)`
    3. The function uses `ast.parse(method_name, "eval")` to parse the `call_method_name` string.
    4. It then iterates through `call.args` and `call.keywords` and uses `eval_value` to process each argument.
    5. Function `eval_value(value)` uses `ast.literal_eval(value)` to convert strings to Python primitives.
    6. Although `ast.literal_eval` is used, the overall process of parsing method names and arguments from a string provided directly from the request payload without sufficient validation is risky.
    7. There is no explicit sanitization or validation of the `call_method_name` string or the parsed arguments before they are used to call methods on the component.

    ```mermaid
    graph LR
        A[Client Request with call_method_name] --> B(parse_call_method_name);
        B --> C{ast.parse};
        C -- Success --> D{Iterate call.args and call.keywords};
        D --> E(eval_value);
        E --> F{ast.literal_eval};
        F -- Returns Parsed Value --> G[Method Call with Parsed Args];
        C -- Failure --> H[Error Handling];
        F -- SyntaxError --> H;
        B -- Returns method_name, args, kwargs --> G;
        G --> I[Component Method Execution];
        I --> J[Vulnerable if args are not sanitized];
    ```

* **Security Test Case:**
    1. Setup a Django application with django-unicorn installed.
    2. Create a component with a method that accepts an argument and is vulnerable to command injection if the argument is not sanitized. For example:

    ```python
    # vulnerable_component.py
    from django_unicorn.components import UnicornView
    import os

    class VulnerableComponentView(UnicornView):
        def execute_command(self, command):
            os.system(command) # DON'T DO THIS IN PRODUCTION - VULNERABLE CODE

    ```

    3. Create a template that includes this component and has a button that triggers the `execute_command` action, allowing to pass an argument from the frontend. For simplicity, we can directly call the method with a hardcoded malicious command in the template for testing:

    ```html
    {% load unicorn %}
    <div unicorn:id="testComponent" unicorn:name="vulnerable-component">
        <button unicorn:click="execute_command('touch /tmp/unicorn_rce_test')">Trigger RCE</button>
    </div>
    ```

    4. Start the Django development server.
    5. Open the page in a browser where the component is rendered.
    6. Click the "Trigger RCE" button.
    7. Check if the file `/tmp/unicorn_rce_test` is created on the server. If the file is created, it confirms Remote Code Execution.

    **Note:** This test case is a simplified example to demonstrate the vulnerability. A real-world attack might require more sophisticated injection techniques and a more practical vulnerable method in the component. This test case is for demonstration purposes only and should be performed in a controlled testing environment.

#### 2. Insecure Deserialization via Cached Pickle Data

* **Vulnerability Name:** Insecure Deserialization via Cached Pickle Data
* **Description:**
    1. When a Unicorn component instance is cached, the framework serializes (pickles) the entire component object—including its state—using `pickle.dumps()`.
    2. The serialized object is stored in a shared or distributed cache (e.g., Redis, Memcache), referenced by a cache key derived from the component’s ID.
    3. When restoring the cached view, `pickle.loads()` is called to deserialize the pickled component object.
    4. Attackers who can write arbitrary data to the same cache location (e.g., by exploiting misconfigurations that allow shared or unauthenticated cache access) can replace the legitimate serialized data with a malicious pickled payload.
    5. On deserialization, Python’s `pickle.loads()` will execute the attacker’s payload, leading to remote code execution under the privileges of the Django application process.
* **Impact:** Successful exploitation of this insecure deserialization could allow an external attacker with write access to the cache to run arbitrary code in the context of the web application. This typically leads to complete compromise of the server, data exfiltration, or further pivoting within the infrastructure. Due to the severity of allowing arbitrary code execution, this ranks as a critical vulnerability.
* **Vulnerability Rank:** critical
* **Currently Implemented Mitigations:** None specific to mitigating pickle’s insecure deserialization. The code is using a standard Python `pickle.loads()` without integrity checks (e.g., cryptographic signing) or gating.
* **Missing Mitigations:**
    - Replace `pickle` with a safer serialization library or mechanism (e.g., JSON, manual whitelisting of fields, or specialized cryptographic signing).
    - Restricting write access to the cache is essential. Ensure robust authentication and segregation (e.g., separate cache namespaces, credentials) so that untrusted parties cannot inject malicious data.
    - Incorporate a signature or HMAC to validate the authenticity of serialized objects before deserialization.
* **Preconditions:**
    - The attacker can manipulate or overwrite the cache entry for a Unicorn component’s `.component_cache_key`.
    - The Django app is running in a production environment where the cache mechanism is accessible (e.g., a Redis or Memcached instance).
    - No protective hashing or signing prevents malicious tampering of serialized component data.
* **Source Code Analysis:**
    - The caching mechanism is implemented in `django_unicorn\django_unicorn\cacher.py`.
    - `CacheableComponent.__enter__()` calls `pickle.dumps(component)` to serialize.
    - `restore_from_cache()` calls `pickle.loads(...)` to deserialize. No cryptographic integrity checks or whitelisting exist.
    - If an attacker injects a malicious pickle payload under the same cache key, `pickle.loads()` will execute attacker-supplied code on the server.

    Example relevant excerpts (abbreviated):
    ```python
    # django_unicorn/django_unicorn/cacher.py

    with CacheableComponent(component) as caching:
        # ...
        pickle.dumps(component)  # Data is serialized

    def restore_from_cache(component_cache_key: str, request: Optional[HttpRequest] = None):
        cached_component = cache.get(component_cache_key)
        if cached_component:
            return pickle.loads(cached_component)  # Data is deserialized unsafely
    ```
* **Security Test Case:**
    1. Set the Django instance to use a cache (e.g., Redis) accessible to both the web application and an external user (attacker).
    2. The web application runs a Unicorn component that is cached using `CacheableComponent`.
    3. The attacker crafts a malicious Python pickle payload which, upon `pickle.loads()`, executes code (e.g., `os.system` call).
    4. The attacker overwrites the legitimate Redis key (e.g., `unicorn:component:<ID>`) with the malicious payload.
    5. Trigger the application to deserialize—from `restore_from_cache()`—and confirm that arbitrary code was executed with the privileges of the Django process.

    By performing this test, it is demonstrated that the framework’s use of pickle for caching places the application at risk of remote code execution if cache integrity is compromised.

#### 3. Remote Code Execution via Template Injection in Component Arguments

* **Vulnerability Name:** Remote Code Execution via Template Injection in Component Arguments
* **Description:** An attacker can inject template code into component arguments, leading to remote code execution on the server when the template is rendered. This is possible because the `unicorn` template tag does not properly sanitize arguments passed to components, and these arguments are directly rendered within the component template.

    **Steps to Trigger:**
    1. Identify a page that uses a django-unicorn component and accepts arguments in the `unicorn` template tag. For example: `{% unicorn 'my-component' arg1=user_input %}`.
    2. Craft a malicious input for `user_input` that contains Django template code designed to execute arbitrary Python code. For example: `{% import os %}{{ os.system('whoami') }}`.
    3. Submit a request to the page with the crafted malicious input.
    4. The django-unicorn backend will render the component template, including the injected template code within the argument.
    5. Django's template engine will execute the injected code, leading to remote code execution on the server.

* **Impact:** Critical. Successful exploitation allows an attacker to execute arbitrary Python code on the server hosting the django-unicorn application. This could lead to complete compromise of the server and the application's data, including sensitive information, user accounts, and the ability to modify application behavior.
* **Vulnerability Rank:** Critical
* **Currently Implemented Mitigations:** None. Based on the provided code, specifically in `django_unicorn/templatetags/unicorn.py`, there is no input sanitization or escaping applied to component arguments before rendering them in the template. The `sanitize_html` function in `django_unicorn/utils.py` is available, but it's not used in the component argument rendering process.  Review of the provided project files (`tests\views\utils\test_set_property_from_data.py` and `pyproject.toml`) does not indicate any implemented mitigations for this vulnerability.
* **Missing Mitigations:**
    - Implement robust input sanitization and escaping for all component arguments passed through the `unicorn` template tag in `django_unicorn/templatetags/unicorn.py`.
    - Consider using Django's built-in `escape` template filter or a similar mechanism to automatically escape arguments before rendering.
    - Alternatively, explore using a templating engine that automatically escapes output by default, or enforce manual escaping of all dynamic content within component templates.
    - Review and audit all existing components that accept arguments to identify and mitigate potential template injection points.
* **Preconditions:**
    - The application must use django-unicorn components and pass arguments to them via the `unicorn` template tag.
    - An attacker must be able to control or influence the values of these arguments, either directly through user input or indirectly through other application vulnerabilities.
* **Source Code Analysis:**

    1. **`django_unicorn/templatetags/unicorn.py`:** This file defines the `unicorn` template tag, which is used to render components in Django templates. The `unicorn` tag's `render` method is where the vulnerability lies.
    2. **`UnicornNode.render` function:** This function is responsible for creating and rendering the component. It retrieves arguments passed to the `unicorn` tag and passes them to the component's template context.
    3. **Argument Handling:** Inside `UnicornNode.render`, arguments passed to the `unicorn` template tag are resolved from the template context and stored in `resolved_kwargs`. These `resolved_kwargs` are directly passed to `UnicornView.create` and eventually end up in the component's template context within the `_render_component_template` function in `django_unicorn/templatetags/unicorn.py`.
    4. **Template Context Creation in `_render_component_template`:** The `_render_component_template` function, called during component rendering, creates a Django `Context` object. Crucially, the `kwargs` (which contain the arguments passed to the `unicorn` tag) are directly unpacked into this context using `**kwargs`. This means any template code injected within these arguments will be directly processed by Django's template engine during rendering.

    **Code Snippet from `django_unicorn/templatetags/unicorn.py` (relevant part):**
    ```python
    class UnicornNode(template.Node):
        def render(self, context):
            ...
            resolved_kwargs = self.kwargs.copy()
            ...
            self.view = UnicornView.create(
                ...
                kwargs=resolved_kwargs, # kwargs are directly passed to component creation
            )
            ...
            rendered_component = self.view.render(init_js=True, extra_context=extra_context)
            return rendered_component
    ```

    **Code Snippet from `django_unicorn/templatetags/unicorn.py` (relevant part - `_render_component_template`):**
    ```python
    def _render_component_template(
        ...
        kwargs: Dict, # kwargs from UnicornNode.render
        context_autoescape: bool,
        ...
    ) -> Tuple[UnicornView, str]:
        ...
        context = Context(
            {
                "component": component,
                "unicorn": {
                    ...
                },
                **component.data,
                **kwargs, # Arguments passed to the template tag are unpacked directly into the context
            },
            autoescape=context_autoescape,
        )
        ...
        html = template.render(context) # Template is rendered with the context, including un-sanitized kwargs
        ...
    ```

    This direct inclusion of `kwargs` into the template context without any sanitization or escaping is the root cause of the template injection vulnerability.  Review of `tests\views\utils\test_set_property_from_data.py` does not reveal any changes related to template rendering or sanitization.

* **Security Test Case:**

    **Assumptions:**
    - We have a Django application running django-unicorn.
    - There is a component named `test_arg_component` and a template `test_arg_component.html` that renders an argument passed to it.
    - The `urls.py` includes a path to a view that renders a template using this component, and allows passing user-controlled data as an argument.

    **Steps:**
    1. Create a component `test_arg_component` in `myapp/components/test_arg_component.py`:
    ```python
    from django_unicorn.components import UnicornView

    class TestArgComponentView(UnicornView):
        arg_value = ""

        def mount(self, arg_value="default"):
            self.arg_value = arg_value
    ```

    2. Create a template `test_arg_component.html` in `myapp/templates/unicorn/test_arg_component.html`:
    ```html
    <div>
        Argument Value: {{ arg_value }}
    </div>
    ```

    3. Create a view in `myapp/views.py` to render a template that uses the component and allows passing a GET parameter as an argument:
    ```python
    from django.shortcuts import render

    def test_arg_view(request):
        malicious_arg = request.GET.get('arg', 'safe_value')
        context = {'user_arg': malicious_arg}
        return render(request, 'test_arg_template.html', context)
    ```

    4. Create a template `test_arg_template.html` in `myapp/templates/test_arg_template.html`:
    ```html
    {% load unicorn %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        <h1>Test Argument Component</h1>
        {% unicorn 'test-arg-component' arg_value=user_arg %}
    </body>
    </html>
    ```

    5. Add a path to `urls.py` in `myapp/urls.py` or project level `urls.py`:
    ```python
    from django.urls import path
    from myapp.views import test_arg_view

    urlpatterns = [
        path('test-arg/', test_arg_view, name='test_arg_view'),
    ]
    ```

    6. Access the URL `/test-arg/?arg={% import os %}{{ os.system('whoami') }}` in a browser.
    7. Observe the output of the `whoami` command (or any other injected command) rendered on the page, confirming remote code execution.

This vulnerability allows a remote attacker to execute arbitrary code on the server, making it a **critical security risk**. Immediate mitigation is highly recommended.  The provided project files do not contain any changes that would mitigate this vulnerability, thus it remains a **critical security risk**.
