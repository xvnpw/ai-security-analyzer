- Vulnerability Name: Improper use of `safe` Meta attribute leading to Cross-Site Scripting (XSS)
- Description:
    - A developer might incorrectly use the `safe` Meta attribute in a Django Unicorn component to mark a property as safe, intending to render HTML content.
    - If this property is directly bound to user input using `unicorn:model` and rendered in the template without further sanitization, a malicious user can inject JavaScript code.
    - When the component re-renders (either through model update or action), the injected JavaScript will be executed in the victim's browser, leading to XSS.
- Impact:
    - Cross-Site Scripting (XSS) vulnerability.
    - An attacker can execute arbitrary JavaScript code in the victim's browser.
    - This can lead to stealing sensitive user data (cookies, session tokens), performing actions on behalf of the user, defacing the website, or redirecting the user to malicious sites.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - By default, Django Unicorn HTML encodes updated field values to prevent XSS attacks. This is the primary mitigation.
    - Documentation in `views.md` mentions the `safe` Meta attribute and its purpose, implicitly warning developers about its usage.
- Missing Mitigations:
    - No explicit server-side sanitization is enforced when the `safe` Meta attribute is used.
    - No warnings or checks during development or runtime to highlight potentially unsafe usage of the `safe` attribute with user inputs.
- Preconditions:
    - A Django Unicorn component is created.
    - This component has a property that is bound to user input using `unicorn:model`.
    - The component's `Meta` class incorrectly marks this user-input property as `safe`.
    - The template renders this `safe` property without any further output escaping.
- Source Code Analysis:
    - File: `..\django-unicorn\docs\source\views.md`
        - Section: `Meta` -> `safe`
        - The documentation explicitly states: "By default, `unicorn` HTML encodes updated field values to prevent XSS attacks. You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple."
        - This confirms that the library provides default encoding as a mitigation, but it allows developers to bypass it using the `safe` attribute.
        - Misuse of `safe` attribute for user inputs without sanitization leads to XSS.
    - File: `..\django-unicorn\tests\views\test_process_component_request.py`
        - Function: `test_safe_html_entities_not_encoded`
        - This test explicitly demonstrates that when a property is marked as `safe` in the `Meta` class, HTML entities are *not* encoded.
        - The test posts data with HTML content (`<b>test1</b>`) to a component where `hello` property is marked as `safe`.
        - The assertion `assert "<b>test1</b>" in response["dom"]` verifies that the HTML content is rendered without encoding, confirming the bypass of default XSS protection when `safe` is used.
    - File: `..\django-unicorn\django_unicorn\components\unicorn_template_response.py`
        - Function: `sanitize_html`
        - This function exists to escape HTML characters for JSON script data, used for component initialization (`init_script`).
        - However, `sanitize_html` is *not* applied to the general component template rendering or when properties marked as `safe` are rendered, meaning the library relies on developer to sanitize `safe` marked content.
        - Analysis of `unicorn_template_response.py` confirms that HTML sanitization in `_desoupify` is for consistent HTML serialization, not for security against XSS. It does not encode HTML entities to prevent script injection.
    - File: `..\django-unicorn\django_unicorn\views\__init__.py`
        - Function: `_process_component_request`
        - This function processes component requests and handles rendering.
        - It retrieves `safe_fields` from the component's `Meta` class.
        - It iterates through `safe_fields` and applies `mark_safe` to the corresponding component attributes *after* user input is set and component methods are called, but *before* rendering.
        - This confirms that `safe` attribute bypasses default HTML encoding, and no other sanitization is automatically applied by the library for these fields before rendering.
    - File: `..\django-unicorn\django_unicorn\views\action_parsers\call_method.py`
        - Function: `handle` and `_call_method_name`
        - These functions handle server-side logic for processing method calls and property updates initiated from the frontend.
        - The code parses method names, arguments, and keyword arguments from the request payload.
        - It uses `parse_call_method_name`, `parse_kwarg`, and `cast_value` to process the incoming data and ensure arguments are correctly passed to the component methods.
        - The code correctly handles type casting and argument parsing for method calls, focusing on server-side processing and does not introduce new XSS vulnerabilities.
        - This file is related to handling user interactions and data processing, but does not directly involve template rendering or output escaping in a way that would create new XSS risks beyond the existing `safe` attribute misuse vulnerability.
- Security Test Case:
    - Step 1: Create a Django Unicorn component named `xss_component` in a Django app.
    - Step 2: In `xss_component.py`, define a component class like this:
        ```python
        from django_unicorn.components import UnicornView

        class XssComponentView(UnicornView):
            user_input = ""

            class Meta:
                safe = ("user_input",)
        ```
    - Step 3: Create a template `xss_component.html` for this component:
        ```html
        <div>
            <input type="text" unicorn:model="user_input" id="user-input">
            <div id="output"> {{ user_input }} </div>
        </div>
        ```
    - Step 4: Include this component in a Django template that is publicly accessible, e.g., in `index.html`:
        ```html
        {% load unicorn %}
        <html>
        <head>
            {% unicorn_scripts %}
        </head>
        <body>
            {% csrf_token %}
            {% unicorn 'xss-component' %}
        </body>
        </html>
        ```
    - Step 5: Run the Django development server.
    - Step 6: Open the page in a browser where the component is included.
    - Step 7: In the input field, enter the following payload: `<script>alert('XSS Vulnerability')</script>`.
    - Step 8: Click outside the input field or trigger an update (if using `lazy` modifier, otherwise the XSS will trigger immediately on input).
    - Step 9: Observe if an alert box with "XSS Vulnerability" appears.
    - Expected Result: An alert box should appear, demonstrating that the JavaScript code was executed, proving the XSS vulnerability due to the improper use of the `safe` attribute. If the alert appears, it confirms the vulnerability. If not, further investigation into encoding mechanisms is required.  **Expected result is that alert box appears.**
