- Vulnerability name: Cross-Site Scripting (XSS) in Component Properties
- Description:
  - An attacker can inject malicious JavaScript code into a component property.
  - This can be achieved by manipulating data that populates component properties, such as URL parameters or form inputs.
  - When the component is rendered, the injected JavaScript code is included in the HTML output without sufficient sanitization.
  - When a user views the page, the malicious JavaScript code gets executed in their browser.
- Impact:
  - An attacker can execute arbitrary JavaScript code in a user's browser.
  - This can lead to session hijacking, cookie theft, redirection to malicious websites, or website defacement.
  - Given Django Unicorn's purpose of enabling dynamic frontend interactions, this vulnerability is particularly critical.
- Vulnerability rank: High
- Currently implemented mitigations:
  - The changelog mentions HTML encoding for updated field values from version v0.36.0 to prevent XSS, but this mitigation might not be consistently applied to all contexts, especially initial property values and might not be sufficient.
- Missing mitigations:
  - Implement comprehensive input sanitization for all component properties that are rendered in templates.
  - Employ context-aware output encoding to sanitize data based on its rendering context within HTML (e.g., HTML entities, JavaScript strings, URLs).
- Preconditions:
  - The application must utilize django-unicorn and render user-supplied or potentially unsafe data within component templates.
  - An attacker needs to identify and exploit data inputs (e.g., URL parameters, form fields) that are directly bound to component properties.
- Source code analysis:
  - File: `django_unicorn\views\__init__.py`
    - The `_process_component_request` function handles the processing of component requests.
    - It iterates through actions in `component_request.action_queue`.
    - For `syncInput` actions, it calls `sync_input.handle`. For `callMethod` actions, it calls `call_method.handle`.
    - **Vulnerability Point:** The code sets component properties using `set_property_from_data` within the loop. This function (as analyzed in previous steps and confirmed by code context) does not perform sanitization on the `property_value` before setting it to the component.
    - The `_process_component_request` function then renders the component using `component.render(request=request)`.
    - **Vulnerability Point:**  The `render` method (inferred from context of `UnicornTemplateResponse` and `UnicornView`) is responsible for rendering the component's template, including component properties. If the component properties are not sanitized before being passed to the template context, they will be rendered as raw HTML, leading to XSS.
    - The code iterates through `safe_fields` and marks them as safe using `mark_safe`.
    - **Mitigation Weakness:** This `mark_safe` mitigation is only applied to fields listed in `Meta.safe`. If developers forget to include user-provided properties in `Meta.safe` and don't manually sanitize them in templates, XSS vulnerability persists. Also, `mark_safe` should be used with caution and understanding of its implications, as it bypasses Django's automatic escaping and should only be used when the content is genuinely safe. In the context of user inputs, relying solely on `mark_safe` without proper sanitization is dangerous.
  - File: `django_unicorn\components\unicorn_template_response.py` (from previous analysis)
    - The `render` method in `UnicornTemplateResponse` is responsible for rendering the component.
    - Review of this method is needed to confirm if and how context variables (component properties) are sanitized before being rendered into the template.
    - Currently, the code focuses on setting attributes like `unicorn:id`, `unicorn:name`, etc., but explicit sanitization of user-provided data within component properties before rendering is not evident in the provided files.
  - File: `django_unicorn\templatetags\unicorn.py` (from previous analysis)
    - The `unicorn` template tag is used to include components in Django templates.
    - Analysis of `UnicornNode.render` is needed to check if there's any sanitization when component data is added to the template context.
    - The code primarily focuses on resolving component names and arguments but does not appear to include explicit sanitization of property values.
  - File: `django_unicorn\views\action_parsers\sync_input.py` and `django_unicorn\views\action_parsers\utils.py` (from previous analysis)
    - These files handle the synchronization of input values to component properties.
    - `sync_input.py` uses `set_property_value` from `utils.py` to update component properties.
    - Review of `set_property_value` in `utils.py` is needed to determine if any sanitization is applied to `property_value` before it's set on the component.
    - The code appears to directly set the `property_value` without sanitization, potentially leading to XSS if the value contains malicious script.
- Security test case:
  - Step 1: Create a Django Unicorn component, for example, named `XssTestComponent`, with a property `userInput` initialized to an empty string, and a template `xss_test_component.html` that renders this property:
    ```html
    <div>
        {{ userInput }}
    </div>
    ```
    and component class `XssTestComponent.py`:
    ```python
    from django_unicorn.components import UnicornView

    class XssTestComponentView(UnicornView):
        userInput: str = ""
    ```
  - Step 2: Create a Django view and template to include this component. In `views.py`:
    ```python
    from django.shortcuts import render
    from .unicorn.components.xss_test_component import XssTestComponentView

    def xss_test_view(request):
        return render(request, 'xss_test_template.html')
    ```
    and in `xss_test_template.html`:
    ```html
    {% load unicorn %}
    {% csrf_token %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% unicorn 'xss-test-component' %}
    </body>
    </html>
    ```
  - Step 3: Modify the `XssTestComponentView` to accept user input, for example, via URL parameter. In `XssTestComponentView.py`:
    ```python
    from django_unicorn.components import UnicornView

    class XssTestComponentView(UnicornView):
        userInput: str = ""

        def mount(self):
            self.userInput = self.request.GET.get('input', '')
    ```
  - Step 4: Access the view with a crafted URL containing malicious JavaScript in the `input` parameter: `http://127.0.0.1:8000/xss-test-view/?input=%3Cimg%20src=x%20onerror=alert('XSS')%3E`
  - Step 5: Inspect the rendered HTML source of `xss_test_template.html`. Verify that the `userInput` property is rendered directly without sanitization:
    ```html
    <div>
        <img src=x onerror=alert('XSS')>
    </div>
    ```
  - Step 6: Observe if the JavaScript code executes when the page loads. An alert box with 'XSS' should appear, confirming the vulnerability.
