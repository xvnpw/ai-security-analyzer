- Cross-Site Scripting (XSS) via Unsanitized Component Properties
    - Description:
        1. An attacker can send a crafted `syncInput` message to modify a component's property.
        2. The `syncInput` action handler (`django_unicorn\views\action_parsers\sync_input.py`) uses `set_property_value` to update the component's property with the value from the message.
        3. `set_property_value` and the related type casting functions in `django_unicorn\typer.py` do not perform HTML sanitization on the input value.
        4. If a component's template renders this property value without proper HTML escaping (e.g., using `{{ property }}` instead of `{{ property|escape }}` or `{% filter force_escape %}`), and the developer has not manually sanitized the data, then the attacker-controlled value will be rendered as raw HTML in the user's browser.
        5. This allows the attacker to inject malicious JavaScript code into the web page, leading to Cross-Site Scripting (XSS).
    - Impact:
        - An attacker can execute arbitrary JavaScript code in the context of the user's browser when they view a page containing a vulnerable Unicorn component.
        - This can lead to session hijacking, cookie theft, defacement of the website, redirection to malicious sites, or other malicious actions.
    - Vulnerability rank: high
    - Currently implemented mitigations:
        - None in the provided code for automatic HTML sanitization of component properties. Developers are responsible for manually sanitizing data if needed before rendering.
    - Missing mitigations:
        - Automatic HTML sanitization should be applied to component properties that are set via `syncInput` before they are rendered in templates. This could be implemented in `set_property_value` function or during template rendering within the Unicorn framework.
        - Recommend developers to use Django's template escaping features (`|escape` or `{% filter force_escape %}`) when rendering user-controlled component properties.
    - Preconditions:
        - A Unicorn component with a property that is rendered in the template without proper HTML escaping.
        - The property must be modifiable via a `syncInput` action (e.g., bound to an input field using `unicorn:model`).
    - Source code analysis:
        1. **`django_unicorn\views\action_parsers\sync_input.py`:**
           - `handle` function receives `component_request` and `payload`.
           - Extracts `property_name` and `property_value` from `payload`.
           - Calls `set_property_value(component, property_name, property_value, component_request.data)`.
        2. **`django_unicorn\views\action_parsers\utils.py`:**
           - `set_property_value` function:
             ```python
             def set_property_value(
                 component, property_name, property_value, data, call_resolved_method=True
             ):
                 # ... (code for nested properties etc.) ...
                 setattr(component, property_name_parts[-1], property_value)
                 data[property_name] = property_value
             ```
           - Directly sets the `property_value` to the component attribute using `setattr` and updates the `data` dictionary. No sanitization is performed here.
        3. **`django_unicorn\typer.py`:**
           - `cast_value` function:
             - Performs type casting based on type hints.
             - Does not perform any HTML sanitization.
        4. **`django_unicorn\components\unicorn_template_response.py`:**
           - `_desoupify` and `sanitize_html` functions are used for JSON data, not for template rendering to prevent XSS.
           - Template rendering uses Django's default template engine, which by default escapes HTML, but if developers use `{% autoescape off %}` or `{% safe %}` or `|safe` filters or raw HTML rendering, they might bypass the default escaping and introduce XSS if component properties are not sanitized.
    - Security test case:
        1. Create a Unicorn component with a string property (e.g., `name`) and render it in the template using `{{ name }}`.
           ```python
           # unicorn/components/xss_test.py
           from django_unicorn.components import UnicornView

           class XssTestView(UnicornView):
               template_name = "unicorn/components/xss_test.html"
               name = "test"
           ```
           ```html
           {# unicorn/components/xss_test.html #}
           <div>
               <input type="text" unicorn:model="name">
               <div id="output">{{ name }}</div>
           </div>
           ```
        2. Create a Django view to render this component.
        3. Open the page in a browser.
        4. In the input field, enter a malicious JavaScript payload like `<img src=x onerror=alert('XSS')>`.
        5. Observe that the `alert('XSS')` dialog box appears, indicating that the JavaScript code was executed.
        6. Check the HTML source of the page in browser's developer tools, and verify that the `div#output` contains the raw, unsanitized JavaScript payload `<img src=x onerror=alert('XSS')>`.
