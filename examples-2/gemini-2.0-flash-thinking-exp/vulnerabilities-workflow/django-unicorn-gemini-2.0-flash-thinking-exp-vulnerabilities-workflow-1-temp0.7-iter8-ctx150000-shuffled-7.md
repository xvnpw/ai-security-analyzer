### Vulnerability List:

#### Vulnerability Name: Cross-Site Scripting (XSS) vulnerability due to unsafe usage of `safe` Meta option

* Description:
    1.  A developer uses the `safe` Meta option in a Django Unicorn component to prevent HTML encoding of a component variable.
    2.  The developer then uses this component variable in a template without further sanitization.
    3.  A malicious user can then inject arbitrary JavaScript code by providing a crafted input that gets assigned to the component variable and rendered in the template without encoding due to the `safe` Meta option.
    4.  When another user views the page, the injected JavaScript code will be executed in their browser, potentially leading to session hijacking, data theft, or other malicious actions.

* Impact:
    *   Cross-site scripting (XSS).
    *   An attacker can execute arbitrary JavaScript code in the victim's browser.
    *   This can lead to session hijacking, cookie theft, redirection to malicious websites, or defacement of the web page.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    *   By default, Django Unicorn HTML encodes updated field values to prevent XSS attacks. This is mentioned in `docs\source\views.md` under the `Meta.safe` section and in `docs\source\changelog.md` for version 0.36.0.
    *   The documentation (`docs\source\views.md`) warns against putting sensitive data into a public property because that information will be publicly available in the HTML source code, unless explicitly prevented with `javascript_exclude`.

* Missing Mitigations:
    *   Django Unicorn project itself does not enforce safe usage of `safe` Meta option. It relies on developers understanding the security implications and using it cautiously.
    *   There is no built-in mechanism to automatically sanitize the output even when `safe` is used.
    *   Lack of clear and prominent warning in the documentation about the high risk of XSS when using `safe` without proper sanitization.

* Preconditions:
    *   A Django Unicorn component uses the `safe` Meta option for a variable.
    *   This variable is rendered in the component's template without proper sanitization (e.g., using Django's `escape` filter or similar).
    *   An attacker can control the value of this component variable, typically through user input bound to the variable with `unicorn:model`.

* Source Code Analysis:
    1.  **`django_unicorn\components\unicorn_template_response.py`**: In the `render` method, the code serializes component data and renders the template. It uses `sanitize_html` function:
        ```python
        json_tag.string = sanitize_html(init)
        ```
    2.  **`django_unicorn\utils.py`**: `sanitize_html` function uses Django's `mark_safe` after escaping HTML entities:
        ```python
        html = html.translate(_json_script_escapes)
        return mark_safe(html)
        ```
    3.  **`django_unicorn\views\process_view.py`**: In `_process_component`, the component is rendered:
        ```python
        rendered_component = component.render(init_js=True, extra_context=extra_context)
        ```
    4.  **`django_unicorn\components\unicorn_view.py`**: The `render` method in `UnicornView` uses `UnicornTemplateResponse`:
        ```python
        def render(self, *, init_js=False, extra_context=None):
            ...
            template_response = UnicornTemplateResponse(
                template=self.get_template_name(),
                request=self.request,
                context=context,
                component=self,
                init_js=init_js,
                **response_kwargs,
            )

            return template_response.render()
        ```
    5.  **`docs\source\views.md`**: Documentation explains the `safe` Meta option:
        ```markdown
        ### safe

        By default, `unicorn` HTML encodes updated field values to prevent XSS attacks. You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple.
        ```
        This shows that by design, `safe` option disables HTML encoding, and the project relies on the developer to handle sanitization if needed. If developer uses `safe` and does not sanitize, XSS vulnerability can occur.

* Security Test Case:
    1.  Create a Django Unicorn component named `xss_safe_component`.
    2.  In the component's Python view (`xss_safe_component.py`), define a variable `unsafe_data` and add `safe = ("unsafe_data",)` to the `Meta` class:
        ```python
        from django_unicorn.components import UnicornView

        class XssSafeView(UnicornView):
            unsafe_data = ""

            class Meta:
                safe = ("unsafe_data",)
        ```
    3.  In the component's template (`xss-safe.html`), render the `unsafe_data` variable directly:
        ```html
        <div>
            {{ unsafe_data }}
        </div>
        ```
    4.  Create a Django template (`xss_test_template.html`) that includes the `xss_safe_component`:
        ```html
        {% load unicorn %}
        <html>
        <head>
            {% unicorn_scripts %}
        </head>
        <body>
            {% csrf_token %}
            {% unicorn 'xss-safe' %}
        </body>
        </html>
        ```
    5.  Create a Django view to render `xss_test_template.html`.
    6.  Access the Django view in a browser. The component will render without any initial `unsafe_data`.
    7.  Using browser developer tools, identify the component's `unicorn:id`.
    8.  Craft a POST request to the Django Unicorn endpoint (`/unicorn/xss-safe-component`) with the following JSON payload, replacing `<component_id>` with the actual component ID from the previous step:
        ```json
        {
          "actionQueue": [
            {
              "type": "syncInput",
              "payload": {
                "name": "unsafe_data",
                "value": "<img src=x onerror=alert('XSS Vulnerability')>"
              }
            }
          ],
          "data": {
            "unsafe_data": ""
          },
          "checksum": "...",
          "id": "<component_id>",
          "epoch": 1678886400
        }
        ```
        Note: You'll need to generate a valid checksum and epoch. You can get a valid checksum by sending a legitimate request first and copying it. Epoch can be any timestamp.
    9.  Send the crafted POST request using `curl` or a similar tool.
    10. Reload the page in the browser. An alert box with "XSS Vulnerability" should appear, demonstrating that the JavaScript code injected through `unsafe_data` was executed.
