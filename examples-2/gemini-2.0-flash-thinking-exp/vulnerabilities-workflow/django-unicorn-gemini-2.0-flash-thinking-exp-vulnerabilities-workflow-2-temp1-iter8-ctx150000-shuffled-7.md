### Vulnerability List

- Vulnerability Name: Cross-Site Scripting (XSS) through `safe` meta option

- Description:
    - Django Unicorn by default HTML encodes component properties to prevent XSS.
    - The `Meta: safe = ("field_name",)` option in a component view class allows developers to bypass this HTML encoding for specific fields.
    - If a developer uses the `safe` option on a field that renders user-controlled data and fails to sanitize or properly escape this data, it can lead to a Cross-Site Scripting (XSS) vulnerability.
    - An attacker can inject malicious Javascript code into the user-controlled data.
    - When the component is rendered, the injected Javascript code will be included in the HTML output without encoding due to the `safe` option.
    - This malicious Javascript will then be executed in a user's browser when the page is loaded or when the component is updated via AJAX.

- Impact:
    - Successful exploitation of this vulnerability allows an attacker to execute arbitrary Javascript code in a user's browser.
    - This can lead to various malicious actions, including:
        - Account takeover by stealing session cookies or credentials.
        - Data theft by accessing sensitive information displayed on the page.
        - Defacement of the website by modifying the page content.
        - Redirection to malicious websites.
        - Performing actions on behalf of the user, such as making unauthorized purchases or changes to account settings.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - HTML encoding is the default behavior for component properties, which mitigates XSS in most cases.
    - The documentation explicitly mentions the `safe` meta option and implies the security risks associated with it by stating "You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple."

- Missing Mitigations:
    - There is no built-in sanitization or escaping mechanism within django-unicorn to automatically handle user-controlled data when the `safe` meta option is used.
    - The documentation could be improved to more strongly emphasize the security risks of using `safe` with user-controlled data and provide concrete examples of how to properly sanitize or escape data if `safe` is absolutely necessary.
    - Security Test Cases should be added to CI to prevent introduction of similar vulnerabilities in the future.

- Preconditions:
    - A developer must explicitly use the `Meta: safe = ("field_name",)` option in a component view class.
    - The `field_name` must be used to render user-controlled data in the component's template.
    - The developer must fail to sanitize or properly escape the user-controlled data before rendering it in the template.

- Source Code Analysis:
    - File: `django_unicorn/views/__init__.py`
    - Function: `_process_component_request`
    - Line ~316:
        ```python
        # Mark safe attributes as such before rendering
        for field_name in safe_fields:
            value = getattr(component, field_name)
            if isinstance(value, str):
                setattr(component, field_name, mark_safe(value))  # noqa: S308
        ```
    - Code Flow:
        1. The `_process_component_request` function is responsible for rendering the component and preparing the JSON response.
        2. It retrieves `safe_fields` by checking for `Meta.safe` in the component view class.
        3. For each `field_name` in `safe_fields`, it gets the corresponding `value` from the component instance.
        4. If the `value` is a string, it uses `mark_safe(value)` to mark it as safe for HTML rendering, effectively bypassing HTML encoding for this field.
        5. The template is then rendered with this context, and the `safe` fields are rendered without further encoding, potentially leading to XSS if the data is user-controlled and contains malicious Javascript.

- Security Test Case:
    - Step 1: Create a new Django app named `vulntest` in the `example` project.
    - Step 2: Create a new Unicorn component named `xss_safe` within the `vulntest` app using the command: `python example/manage.py startunicorn vulntest xss_safe`.
    - Step 3: Modify the component view class `example/vulntest/components/xss_safe.py` to include the `safe` meta option and a field to render user input:
        ```python
        from django_unicorn.components import UnicornView

        class XssSafeView(UnicornView):
            user_input = ""

            class Meta:
                safe = ("user_input",)
        ```
    - Step 4: Modify the component template `example/vulntest/templates/unicorn/xss-safe.html` to render the `user_input` field:
        ```html
        <div>
            <input type="text" unicorn:model="user_input">
            <div id="output">
                {{ user_input }}
            </div>
        </div>
        ```
    - Step 5: Include the `xss_safe` component in a Django template, for example, modify `example/www/templates/www/index.html`:
        ```html
        {% extends "www/base.html" %}
        {% load unicorn %}

        {% block content %}
        <h1>Django Unicorn Examples</h1>

        {% unicorn 'vulntest.xss_safe' %}

        {% endblock %}
        ```
    - Step 6: Run the Django development server: `python example/manage.py runserver`.
    - Step 7: Open a browser and navigate to `http://127.0.0.1:8000/`.
    - Step 8: In the input field of the "xss_safe" component, enter the following Javascript code: `<img src='x' onerror='alert("XSS Vulnerability")'>`.
    - Step 9: Observe that an alert box with the message "XSS Vulnerability" is displayed in the browser. This confirms that the Javascript code was executed, demonstrating the XSS vulnerability due to the use of `safe` meta option without proper sanitization.
