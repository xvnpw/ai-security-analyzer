### Potential XSS vulnerability due to unsafe string formatting in template rendering

* Vulnerability Name: Potential XSS vulnerability due to unsafe string formatting in template rendering
* Description:
    - An attacker could potentially inject malicious JavaScript code into component properties that are not properly sanitized before being rendered in the HTML.
    - This could occur if a component property is modified via user input through actions like `syncInput` or method calls and this property is rendered in the template without proper escaping, especially when developers explicitly bypass default Django escaping mechanisms.
    - Step 1: Identify a component and a property rendered in a template that is vulnerable to XSS. This vulnerability is exposed when a developer uses `Meta.safe` attribute in a component or `safe` template filter in the template, intending to render HTML without escaping.
    - Step 2: Craft a malicious input that sets the vulnerable property to a JavaScript payload (e.g., `<img src=x onerror=alert(document.domain)>`). This can be done by manipulating input fields bound to component properties using `unicorn:model` or by crafting specific parameters for methods called via `unicorn:click` or similar directives.
    - Step 3: Trigger an action that updates the vulnerable property with the malicious payload. This could be a `syncInput` event when a user types into an input field, or a `callMethod` action when a button is clicked and a method is called that updates the property.
    - Step 4: The component re-renders, and because the output is marked as safe (via `Meta.safe` or `safe` filter) and no additional sanitization is performed by django-unicorn in this specific path, the JavaScript payload executes in the user's browser.
* Impact: Cross-site scripting (XSS). An attacker could execute arbitrary JavaScript code in the victim's browser, potentially leading to session hijacking, account takeover, defacement, or redirection to malicious sites.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - Django's automatic HTML escaping is used by default in templates.
    - The `safe` Meta attribute and `safe` template filter are explicitly mentioned as a way to bypass encoding, implicitly suggesting developer awareness of XSS risks, and implying developers should handle sanitization when using these features.
    - `django_unicorn.utils.sanitize_html` function is used in `django_unicorn\components\unicorn_template_response.py` to sanitize initial data being passed to Javascript on initial render.
* Missing Mitigations:
    - User inputs that modify component properties, especially through `syncInput` and `callMethod` actions, are not consistently sanitized before being rendered. Specifically, when `Meta.safe` or `safe` template filter are used, django-unicorn does not re-apply sanitization to the output. The `sanitize_html` function is used only for initial data, not for subsequent dynamic updates of component properties. There is no automatic sanitization of properties being set via actions in files like `django_unicorn\views\action_parsers\utils.py` or `django_unicorn\views\action_parsers\call_method.py` before template rendering.
* Preconditions:
    - A component must render a property in its template that is directly or indirectly influenced by user input.
    - The developer must use `Meta.safe` on the component or the `safe` filter in the template when rendering the user-influenced property to bypass default Django escaping.
    - User input must be able to modify the component property, for example through `unicorn:model` binding or `callMethod` actions.
* Source Code Analysis:
    - File: `django_unicorn\components\unicorn_template_response.py`
        - `UnicornTemplateResponse.render` method renders the component.
        - `get_frontend_context_variables` method in `UnicornView` prepares data for initial render and applies `sanitize_html` to this initial data.
        - The template rendering itself relies on Django's template engine, which defaults to HTML escaping unless `safe` filter or `Meta.safe` is used.
    - File: `django_unicorn\views\message.py`
        - `_process_component_request` renders the component via `component.render(request=request)` after processing actions.
        - It's unclear if there's consistent output sanitization applied to the component's properties right before this final render, especially for properties that have been modified via actions in this request cycle.
    - File: `django_unicorn\views\action_parsers\call_method.py`
        - `handle` function processes `callMethod` actions, including special actions and regular method calls.
        - `set_property_value` from `django_unicorn\views\action_parsers\utils.py` is used to update component properties when handling setters (e.g., `property_name=value`) within method calls or for special actions like `$toggle`.
    - File: `django_unicorn\views\action_parsers\utils.py`
        - `set_property_value` function:
            ```python
            def set_property_value(component, property_name, property_value, data=None):
                # ... (nested property handling) ...
                setattr(component_or_field, property_name_part, property_value)
                if data is not None:
                    data[property_name] = property_value
            ```
            - This function directly uses `setattr` to set the property value on the component. There is no HTML sanitization applied to `property_value` before setting it, meaning if a malicious payload is provided as `property_value` and the developer uses `Meta.safe` or `safe` filter on this property in the template, XSS is possible.
    - Visualization:
        ```
        User Input --> HTTP Request (Action: syncInput/callMethod, Payload: malicious JS) --> django-unicorn view (message.py) --> Action Parser (call_method.py) --> set_property_value (utils.py) --> Component Property (malicious JS stored) --> UnicornTemplateResponse.render (unicorn_template_response.py) --> Template Rendering (property rendered UNSANITIZED due to 'safe' usage) --> HTML Response (malicious JS executes in browser)
        ```

* Security Test Case:
    - Step 1: Create a component `XssTestComponent` with a property `xss_payload` initialized to an empty string and marked as `safe` in `Meta`.
        ```python
        from django_unicorn.components import UnicornView

        class XssTestComponent(UnicornView):
            xss_payload: str = ""

            class Meta:
                safe = ("xss_payload",)
        ```
    - Step 2: Create the component's template `xss_test_component.html` and render the `xss_payload` within a div without additional escaping. Add an input field bound to `xss_payload` using `unicorn:model`.
        ```html
        <div>{{ xss_payload }}</div>
        <input type="text" unicorn:model="xss_payload">
        ```
    - Step 3: Create a Django template (e.g., `xss_test.html`) to render this component.
        ```html
        {% load unicorn %}
        <!DOCTYPE html>
        <html>
        <head><title>XSS Test</title></head>
        <body>
            {% unicorn 'xss-test-component' %}
        </body>
        </html>
        ```
    - Step 4: Create a Django view to render `xss_test.html`.
        ```python
        from django.shortcuts import render
        from django.views.generic import TemplateView

        class XssTestView(TemplateView):
            template_name = 'xss_test.html'
        ```
    - Step 5: Define a URL pattern to access `XssTestView`.
    - Step 6: As an attacker, access the page in a browser.
    - Step 7: In the input field, enter a JavaScript payload: `<img src=x onerror=alert('XSS')>`.
    - Step 8: Trigger a `syncInput` event by blurring the input field or pressing Enter.
    - Step 9: Observe if an alert box with 'XSS' is displayed in the browser. If yes, the vulnerability is confirmed.
    - Step 10: Inspect the rendered HTML source code using browser developer tools. Confirm that the malicious payload `<img src=x onerror=alert('XSS')>` is inserted directly within the `<div>` element without any HTML escaping.
