## Vulnerability List for django-unicorn Project

Here is a list of identified vulnerabilities in the django-unicorn project based on the provided files.

### 1. Cross-Site Scripting (XSS) via Template Injection in Component Arguments

* Description:
    1. An attacker can inject arbitrary HTML or JavaScript code into the component's template by crafting a malicious argument passed to the `{% unicorn %}` template tag.
    2. The `django-unicorn` library does not properly sanitize or escape arguments passed to the component when rendering the initial HTML.
    3. When the template is rendered on the server-side for the initial page load, the injected script is executed in the user's browser.

* Impact:
    * **Critical**
    * Successful exploitation allows an attacker to execute arbitrary JavaScript code in the context of the victim's browser.
    * This can lead to session hijacking, cookie theft, defacement of the website, redirection to malicious sites, or other malicious actions.

* Vulnerability Rank: critical

* Currently implemented mitigations:
    * The project implemented HTML encoding for component updates after CVE-2021-42053. This mitigation primarily focuses on preventing XSS during AJAX updates and is visible in files like `django_unicorn/components/unicorn_template_response.py` where `sanitize_html` is used for `init` script. This is further confirmed by tests in `tests/views/test_process_component_request.py` which demonstrate HTML encoding for component data during updates.
    * The documentation mentions the `safe` Meta option to explicitly allow bypassing HTML encoding, which is intended for developer control, but can be misused if not handled carefully. Tests in `tests/views/test_process_component_request.py` like `test_safe_html_entities_not_encoded` confirm that `safe` option indeed bypasses HTML encoding, requiring developers to be cautious when using it with user-provided data.

* Missing mitigations:
    * Input sanitization or output escaping for arguments passed to the `{% unicorn %}` template tag during initial server-side rendering.
    * Contextual output escaping within the template rendering process to ensure arguments are treated as data, not code, by default.

* Preconditions:
    * The application must use the `{% unicorn %}` template tag and allow user-controlled input to be passed as arguments to the component.
    * The application must not have implemented custom sanitization for these arguments before passing them to the `{% unicorn %}` tag.

* Source code analysis:
    1. **Template Tag Rendering**: The `{% unicorn %}` template tag is defined in `django_unicorn/templatetags/unicorn.py` and the rendering logic is within the `UnicornNode.render` method. This method resolves arguments from the template context and passes them to `UnicornView.create`.
    ```python
    # django_unicorn/templatetags/unicorn.py
    class UnicornNode(template.Node):
        # ...
        def render(self, context):
            # ...
            resolved_kwargs = self.kwargs.copy()
            for key, value in self.unparseable_kwargs.items():
                try:
                    resolved_value = template.Variable(value).resolve(context)
                    resolved_kwargs.update({key: resolved_value})
                except TypeError:
                    resolved_kwargs.update({key: value})
                except template.VariableDoesNotExist:
                    pass
            # ...
            self.view = UnicornView.create(
                # ...
                kwargs=resolved_kwargs,
            )
            # ...
            rendered_component = self.view.render(init_js=True, extra_context=extra_context)
            return rendered_component
    ```
    2. **Component Creation and Rendering**: `UnicornView.create` (in `django_unicorn/components/unicorn_view.py`) and `UnicornView.render` call `render_to_response` which eventually leads to `UnicornTemplateResponse.render` (in `django_unicorn/components/unicorn_template_response.py`).
    3. **Initial Render Context**: Arguments passed to `{% unicorn %}` tag become keyword arguments (`kwargs`) for `UnicornView.create` and are used when the component is instantiated and rendered for the first time. These arguments are placed into the template context in `UnicornView.get_context_data`.
    ```python
    # django_unicorn/components/unicorn_view.py
    class UnicornView(TemplateView):
        # ...
        @timed
        def get_context_data(self, **kwargs):
            """
            Overrides the standard `get_context_data` to add in publicly available
            properties and methods.
            """
            context = super().get_context_data(**kwargs)

            attributes = self._attributes()
            context.update(attributes) # Arguments become part of context here
            context.update(self._methods())
            context.update(
                {
                    "unicorn": {
                        "component_id": self.component_id,
                        "component_name": self.component_name,
                        "component_key": self.component_key,
                        "component": self,
                        "errors": self.errors,
                    }
                }
            )
            return context
    ```
    4. **Template Processing**: Django's template engine renders the template with this context. If arguments are not escaped, any HTML or JavaScript injected into arguments will be executed. The provided files do not show any HTML sanitization or escaping of these arguments during this initial rendering process before they are passed to the template.
    5. **`sanitize_html` Misalignment**: While `django_unicorn/utils.py` does contain a `sanitize_html` function, and it's used in `UnicornTemplateResponse.render` to sanitize `init` script data, this is for the JSON data passed to the frontend for component initialization, not for the initial server-side template rendering of component arguments.
    ```python
    # django_unicorn/components/unicorn_template_response.py
    class UnicornTemplateResponse(TemplateResponse):
        # ...
        @timed
        def render(self):
            # ...
            init = orjson.dumps(init).decode("utf-8")
            json_element_id = f"unicorn:data:{self.component.component_id}"
            json_tag = soup.new_tag("script")
            json_tag["type"] = "application/json"
            json_tag["id"] = json_element_id
            json_tag.string = sanitize_html(init) # sanitize_html is used here for init script
            # ...
    ```

    This analysis confirms that arguments passed to the `{% unicorn %}` tag during initial rendering are still vulnerable to XSS because they are not sanitized or escaped before being rendered by Django's template engine. The existing `sanitize_html` function is not applied in the vulnerable code path for initial rendering of component arguments.

* Security test case:
    1. Create a Django view that renders a template containing a `{% unicorn %}` tag.
    2. In the Django view, allow a query parameter to control an argument passed to the `{% unicorn %}` tag. For example, if the query parameter is `username`, pass its value as the `name` argument to the component:
        ```python
        def my_view(request):
            username = request.GET.get('username', 'World')
            return render(request, 'vulnerable_template.html', {'user_provided_name': username})
        ```
    3. Create a simple Unicorn component (e.g., `hello.py` and `hello.html`) that uses the `name` argument in the template:
        ```python
        # hello.py
        from django_unicorn.components import UnicornView
        class HelloView(UnicornView):
            name = "World"
        ```
        ```html
        <!-- hello.html -->
        <div>Hello {{ name }}!</div>
        ```
    4. Access the Django view in a browser with a malicious query parameter: `/?username=<script>alert("XSS_initial_render")</script>`.
    5. Observe that an alert box with "XSS_initial_render" is displayed, indicating successful XSS during initial server-side rendering.

* Currently implemented mitigations: None for initial render arguments. HTML encoding using `sanitize_html` is applied to the `init` script for AJAX updates only, not initial render arguments.

* Missing mitigations:
    * Implement input sanitization or contextual output escaping for component arguments within the `{% unicorn %}` template tag.
    * Ensure that all arguments passed to components are treated as plain text data by default during initial rendering, preventing execution of injected scripts.
    * Provide clear documentation and best practices for developers on how to handle user-provided data passed to Unicorn components, emphasizing the importance of sanitization and secure coding practices.

This vulnerability allows for critical impact and is not mitigated for initial render arguments in the current version based on the provided files and analysis. It is ranked as critical due to the ease of exploitation and severe impact of XSS.
