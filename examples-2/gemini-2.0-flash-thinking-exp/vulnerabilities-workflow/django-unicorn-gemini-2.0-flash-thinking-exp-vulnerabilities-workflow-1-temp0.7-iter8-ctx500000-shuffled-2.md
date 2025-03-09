## Vulnerability List for django-unicorn Project

### Reflected Cross-Site Scripting (XSS) via Component Arguments

*   **Vulnerability Name:** Reflected Cross-Site Scripting (XSS) via Component Arguments
*   **Description:** Django-unicorn allows passing arguments to components directly in templates using the `{% unicorn 'component_name' arg1 kwarg1=value1 ... %}` syntax. These arguments are processed and made available within the component's context. However, if these arguments are not properly sanitized and are directly rendered in the component's template, it can lead to a reflected Cross-Site Scripting (XSS) vulnerability. An attacker can craft a URL that includes malicious JavaScript code as a component argument. When the server renders the page, this malicious script will be executed in the user's browser.
*   **Impact:** High. Successful exploitation allows an attacker to execute arbitrary JavaScript code in the victim's browser, potentially leading to session hijacking, cookie theft, defacement, or redirection to malicious sites.
*   **Vulnerability Rank:** High
*   **Currently Implemented Mitigations:** The project [changelog](..\django-unicorn\docs\source\changelog.md) mentions a security fix for CVE-2021-42053 in version 0.36.0 to prevent XSS attacks by HTML encoding responses. However, this mitigation might not be sufficient in all cases, especially when developers are directly rendering component arguments without explicit sanitization in their templates. The documentation [views.md](..\django-unicorn\docs\source\views.md) mentions the `safe` Meta attribute to bypass HTML encoding, which if misused, can re-introduce XSS vulnerabilities.
*   **Missing Mitigations:**
    *   Input sanitization of component arguments at the framework level before rendering them in templates. Django's template auto-escaping might not be sufficient if developers explicitly use the `safe` filter or `safe` Meta attribute.
    *   Guidance in documentation to developers about the risks of rendering unsanitized user-provided data in component templates, even if passed as component arguments. Emphasize the need for manual sanitization or using Django's auto-escaping effectively and cautiously using `safe`.
*   **Preconditions:**
    *   The application must be using django-unicorn and rendering components with arguments passed directly from templates.
    *   A component template must be rendering the component argument directly without proper HTML escaping.
*   **Source Code Analysis:**
    1.  **`django_unicorn/templatetags/unicorn.py`:** The `unicorn` template tag parses arguments passed to the component:
        ```python
        def unicorn(parser, token):
            # ...
            component_name = parser.compile_filter(contents[1])
            # ...
            for arg in contents[2:]:
                # ... parsing args and kwargs ...
            return UnicornNode(component_name, args, kwargs, unparseable_kwargs)
        ```
    2.  **`django_unicorn/templatetags/unicorn.py`:** The `UnicornNode.render` method resolves these arguments and passes them to the component:
        ```python
        class UnicornNode(template.Node):
            def render(self, context):
                # ...
                resolved_args = []
                for value in self.args:
                    resolved_arg = template.Variable(value).resolve(context)
                    resolved_args.append(resolved_arg)

                resolved_kwargs = self.kwargs.copy()
                # ... resolve kwargs ...

                self.view = UnicornView.create(
                    # ...
                    component_args=resolved_args,
                    kwargs=resolved_kwargs,
                )
                # ... render component ...
        ```
    3.  **`django_unicorn/components/unicorn_view.py`:** The `UnicornView.create` method instantiates the component and passes the resolved arguments:
        ```python
        class UnicornView(TemplateView):
            @staticmethod
            def create(
                *,
                component_id: str,
                component_name: str,
                component_key: str = "",
                parent: Optional["UnicornView"] = None,
                request: Optional[HttpRequest] = None,
                use_cache=True,
                component_args: Optional[List] = None,
                kwargs: Optional[Dict[str, Any]] = None,
            ) -> "UnicornView":
                # ...
                component = construct_component(
                    # ...
                    component_args=component_args,
                    kwargs=kwargs,
                )
                # ...
        ```
    4.  **`django_unicorn/components/unicorn_view.py`:** The `construct_component` function instantiates the component class with these arguments. Then, within a component template, these arguments can be directly rendered:
        ```html
        <!-- Example vulnerable component template (vulnerable_component.html) -->
        <div>
            Argument: {{ component_args.0 }}  {# Vulnerable if arg is not sanitized #}
            Keyword Argument: {{ component_kwargs.name }} {# Vulnerable if kwarg is not sanitized #}
        </div>
        ```
    5.  If a developer uses such a template and renders a component like `{% unicorn 'vulnerable_component' "<script>alert('XSS')</script>" name="<script>alert('XSS')</script>" %}`, and if `vulnerable_component.html` renders `component_args.0` or `component_kwargs.name` directly without escaping, XSS will occur.

*   **Security Test Case:**
    1.  Create a new django-unicorn component named `xss_arg_component` in your Django application:
        ```python
        # components/xss_arg_component.py
        from django_unicorn.components import UnicornView

        class XssArgComponentView(UnicornView):
            arg1 = ""
            kwarg1 = ""

            def mount(self):
                self.arg1 = self.component_args[0] if self.component_args else ""
                self.kwarg1 = self.component_kwargs.get('kwarg1', '')
        ```
        ```html
        <!-- templates/unicorn/xss-arg-component.html -->
        <div>
            Argument 1: {{ component_args.0 }}
            Keyword Argument 1: {{ component_kwargs.kwarg1 }}
        </div>
        ```
    2.  Create a Django view and template to include this component:
        ```python
        # views.py
        from django.shortcuts import render

        def xss_arg_test_view(request):
            return render(request, 'xss_arg_test.html')
        ```
        ```html
        <!-- templates/xss_arg_test.html -->
        {% load unicorn %}
        <html>
        <head>
            {% unicorn_scripts %}
        </head>
        <body>
            {% csrf_token %}
            {% unicorn 'xss-arg-component' "<script>alert('XSS_ARGUMENT')</script>" kwarg1="<script>alert('XSS_KWARG')</script>" %}
        </body>
        </html>
        ```
    3.  Configure URL in `urls.py`:
        ```python
        # urls.py
        from django.urls import path
        from .views import xss_arg_test_view

        urlpatterns = [
            path('xss-arg-test/', xss_arg_test_view, name='xss_arg_test'),
            path("unicorn/", include("django_unicorn.urls")),
        ]
        ```
    4.  Run the Django development server.
    5.  Access the URL `/xss-arg-test/` in a web browser.
    6.  Observe that JavaScript alerts with "XSS_ARGUMENT" and "XSS_KWARG" are displayed, demonstrating the XSS vulnerability.

### Potential Cross-Site Scripting (XSS) via `unicorn:ignore` and JavaScript Integration

*   **Vulnerability Name:** Potential Cross-Site Scripting (XSS) via `unicorn:ignore` and JavaScript Integration
*   **Description:** The `unicorn:ignore` attribute is designed to prevent django-unicorn from morphing elements and their children, which is useful when integrating with JavaScript libraries that directly manipulate the DOM. However, if a developer uses `unicorn:ignore` on a section of the template that includes user-controlled data and relies on JavaScript to dynamically insert content into this ignored section without proper sanitization, it can lead to a DOM-based XSS vulnerability. An attacker could potentially inject malicious scripts through other parts of the application that are then dynamically rendered into the ignored section by client-side JavaScript, bypassing django-unicorn's server-side HTML encoding.
*   **Impact:** High. Successful exploitation allows an attacker to execute arbitrary JavaScript code in the victim's browser. This is a DOM-based XSS, which can be harder to detect by server-side security measures.
*   **Vulnerability Rank:** High
*   **Currently Implemented Mitigations:** Django-unicorn itself HTML-encodes server responses. The `unicorn:ignore` attribute explicitly tells django-unicorn to not touch the DOM within that element, effectively delegating security responsibility to the developer's custom JavaScript code. The documentation [templates.md](..\django-unicorn\docs\source\templates.md) mentions `unicorn:ignore` and its use case with libraries like `Select2`, but does not explicitly warn about the potential security implications when handling user-provided data in ignored sections.
*   **Missing Mitigations:**
    *   Explicit warning in the documentation about the security risks of using `unicorn:ignore` when handling user-provided data. Documentation should emphasize that developers are solely responsible for sanitizing data rendered within `unicorn:ignore` blocks using JavaScript.
    *   Potentially explore options to provide utility functions or guidance for developers on how to securely handle dynamic content within `unicorn:ignore` blocks.
*   **Preconditions:**
    *   The application must be using django-unicorn and implementing JavaScript integration.
    *   A component template must be using `unicorn:ignore` to prevent morphing of a section of the DOM.
    *   Client-side JavaScript code must be dynamically inserting user-controlled data into the `unicorn:ignore` section without proper sanitization.
*   **Source Code Analysis:**
    1.  **`django_unicorn/components/unicorn_template_response.py`:** The morphing logic in `UnicornTemplateResponse.render` respects the `unicorn:ignore` attribute:
        ```python
        class UnicornTemplateResponse(TemplateResponse):
            @timed
            def render(self):
                # ...
                soup = BeautifulSoup(content, features="html.parser")
                # ...
                for element in soup.descendants:
                    if isinstance(element, Tag):
                        if element.has_attr("unicorn:ignore"):
                            # Skip morphing for this element and its children
                            continue
                        # ... morphing logic ...
        ```
    2.  **`docs/source/templates.md`:** The documentation explains `unicorn:ignore`:
        ```markdown
        ## Ignore elements

        Some JavaScript libraries will change the DOM (such as `Select2`) after the page renders. That can cause issues for `Unicorn` when trying to merge that DOM with what `Unicorn` _thinks_ the DOM should be. `unicorn:ignore` can be used to prevent `Unicorn` from morphing that element or its children.
        ```
    3.  This mechanism itself is not vulnerable, but it creates a situation where developers might inadvertently introduce DOM-based XSS if they are not careful with how they handle dynamic content within the ignored sections using JavaScript.

*   **Security Test Case:**
    1.  Create a new django-unicorn component named `xss_ignore_component` in your Django application:
        ```python
        # components/xss_ignore_component.py
        from django_unicorn.components import UnicornView

        class XssIgnoreComponentView(UnicornView):
            user_input = ""
        ```
        ```html
        <!-- templates/unicorn/xss-ignore-component.html -->
        <div>
            <div unicorn:ignore>
                <div id="ignored-content">
                    <!-- Content will be dynamically inserted here by JavaScript -->
                </div>
            </div>

            <input type="text" unicorn:model="user_input" id="userInput">
            <button unicorn:click="$refresh">Refresh</button>

            <script>
                document.addEventListener('DOMContentLoaded', function() {
                    let userInputElement = document.getElementById('userInput');
                    let ignoredContentElement = document.getElementById('ignored-content');

                    userInputElement.addEventListener('input', function() {
                        // Dynamically insert user input without sanitization into the ignored section
                        ignoredContentElement.innerHTML = userInputElement.value;
                    });
                });
            </script>
        </div>
        ```
    2.  Create a Django view and template to include this component:
        ```python
        # views.py
        from django.shortcuts import render

        def xss_ignore_test_view(request):
            return render(request, 'xss_ignore_test.html')
        ```
        ```html
        <!-- templates/xss_ignore_test.html -->
        {% load unicorn %}
        <html>
        <head>
            {% unicorn_scripts %}
        </head>
        <body>
            {% csrf_token %}
            {% unicorn 'xss-ignore-component' %}
        </body>
        </html>
        ```
    3.  Configure URL in `urls.py`:
        ```python
        # urls.py
        from django.urls import path
        from .views import xss_ignore_test_view

        urlpatterns = [
            path('xss-ignore-test/', xss_ignore_test_view, name='xss_ignore_test'),
            path("unicorn/", include("django_unicorn.urls")),
        ]
        ```
    4.  Run the Django development server.
    5.  Access the URL `/xss-ignore-test/` in a web browser.
    6.  In the input field, type `<img src=x onerror=alert('DOM_XSS')>` and click outside the input or refresh the component using the button.
    7.  Observe that a JavaScript alert with "DOM_XSS" is displayed, demonstrating the DOM-based XSS vulnerability due to unsanitized dynamic insertion into the `unicorn:ignore` section.
