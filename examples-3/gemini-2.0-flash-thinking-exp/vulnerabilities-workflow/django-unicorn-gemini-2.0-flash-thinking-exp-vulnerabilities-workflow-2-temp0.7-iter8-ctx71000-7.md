- Vulnerability Name: Cross-Site Scripting (XSS) through Unsanitized User Input in Component Templates

- Description:
    - An attacker can inject malicious JavaScript code into user-provided data.
    - When a Django Unicorn component renders a template that includes this unsanitized user data, the JavaScript code is executed in the victim's browser.
    - This can occur through `unicorn:model` attributes that bind user input to component properties, which are then rendered in the template.
    - If the component template does not properly sanitize these properties before rendering them into the DOM, an XSS vulnerability is present.
    - For example, if a component property `name` is bound to an input field using `unicorn:model="name"` and the template directly renders `{{ name }}`, an attacker can input `<script>alert('XSS')</script>` into the input field. Upon component update, this script will be executed.

- Impact:
    - Successful XSS attacks can lead to:
        - Account takeover: Attacker can steal session cookies or credentials.
        - Data theft: Attacker can access sensitive information displayed on the page.
        - Malware distribution: Attacker can redirect users to malicious websites or inject malware.
        - Defacement: Attacker can alter the appearance of the web page.
        - Phishing: Attacker can create fake login forms to steal user credentials.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - HTML encoding of responses by default since version 0.36.0.
    - According to `changelog.md` "responses will be HTML encoded going forward (to explicitly opt-in to previous behavior use [safe](views.md#safe))". This mitigation is applied globally by Django template engine's auto-escaping unless the `safe` template filter or `Meta.safe` option is explicitly used to mark a variable as safe.
    - The `sanitize_html` function in `django_unicorn.utils` escapes HTML/XML special characters for use in JSON, and is used when creating the initial component data script tag. This is not a general input sanitization for template rendering but rather for data serialization in JSON.

- Missing Mitigations:
    - No clear guidance in the provided documentation on best practices for sanitizing user input within Django Unicorn component templates, especially when opting out of default HTML encoding using `safe` template filter or `Meta.safe` component option.
    - Lack of specific input sanitization functions or utilities provided by Django Unicorn itself for use within templates when rendering user-provided content. Developers are expected to rely on Django's template auto-escaping (which is default) or implement their own sanitization when using `safe`, but this is not explicitly documented as a security requirement for user-provided input in components.
    - The `Meta.safe` option in components allows developers to bypass the default HTML escaping. While this can be useful for intentionally rendering HTML, it introduces a risk if used incorrectly with user-provided data without proper sanitization. There is no clear documentation on the security implications of using `Meta.safe` and how to use it safely.

- Preconditions:
    - A Django Unicorn component template renders user-provided data from a component property without proper sanitization.
    - User-provided data is bound to a component property using `unicorn:model`.
    - An attacker has the ability to input and submit malicious JavaScript code through the user interface.
    - The developer uses the `safe` template filter or `Meta.safe` option, either intentionally or unintentionally bypassing default auto-escaping for user-provided input.

- Source Code Analysis:
    - Based on documentation, specifically `architecture.md`, Django Unicorn updates the DOM by sending HTML from the server and using `morphdom` to apply changes. If the HTML generated on the server contains unsanitized user input, `morphdom` will render it in the DOM, leading to XSS.
    - `docs/source/actions.md` and other documentation files demonstrate binding user input to component properties and rendering them in templates, e.g., `Hello {{ name|title }}`. If `name` is user-controlled and not sanitized, it's vulnerable, especially if `safe` filter is used: `Hello {{ name|safe }}`.
    - `changelog.md` entries for versions 0.36.0 and 0.36.1 confirm past XSS vulnerabilities and the mitigation of default HTML encoding. The existence of the `safe` option introduces a potential bypass if used incorrectly.
    - `django_unicorn/utils.py` contains `sanitize_html` function, but it's primarily used for escaping HTML for JSON data in the init script within `UnicornTemplateResponse.render`. It is not automatically applied to user input rendered in component templates. The file `django-unicorn\tests\test_utils.py` contains test `test_sanitize_html` which confirms that `sanitize_html` function escapes HTML/XML special characters to be safe in JSON context.
    - `django_unicorn/components/unicorn_view.py` in `_set_property` and `views/action_parsers/utils.py` in `set_property_value` do not include any input sanitization logic. They directly set the provided value to the component property. Files `django-unicorn\tests\views\test_set_property_value.py`, `django_unicorn\tests\views\test_unicorn_dict.py`, `django_unicorn\tests\views\test_unicorn_field.py`, `django_unicorn\tests\views\test_unicorn_model.py`, `django_unicorn\tests\views\test_unicorn_view_init.py` contain tests for property setting and initialization, none of them include sanitization. Furthermore, the file `django_unicorn\tests\views\utils\test_set_property_from_data.py` includes tests for `set_property_from_data` function which is used to set component properties from data received from the client. These tests cover various data types like strings, integers, datetimes, lists, models, and querysets, but they do not include any checks or logic for sanitizing input data during property setting, reinforcing that sanitization is not a default behavior in Django Unicorn's property handling.
    - `django_unicorn/views/__init__.py` in `_process_component_request` applies `mark_safe` to attributes listed in `Meta.safe` *after* rendering, which means the template is rendered without escaping for these attributes if `safe` is used. This can be dangerous if `Meta.safe` is used with user-provided data without prior sanitization. File `django_unicorn\tests\views\test_process_component_request.py` contains tests `test_html_entities_encoded` and `test_safe_html_entities_not_encoded` which demonstrate that default behaviour is HTML encoding, and `Meta.safe` or `safe` filter bypasses encoding.

- Security Test Case:
    - Step 1: Create a Django Unicorn component with a property, e.g., `message`, and bind it to an input field in the template using `unicorn:model="message"`.
    - Step 2: In the component template, render the `message` property directly without any sanitization but with `safe` filter, e.g., `<div>{{ message|safe }}</div>`. Alternatively, use `Meta.safe = ("message",)` in the component and render `<div>{{ message }}</div>`.
    - Step 3: Deploy the Django application with this component to a publicly accessible instance.
    - Step 4: As an external attacker, access the page containing the component through a web browser.
    - Step 5: In the input field, enter the following XSS payload: `<script>alert('XSS Vulnerability')</script>`.
    - Step 6: Trigger a component update, for example, by clicking a button that performs an action or by leaving the input field (if using `unicorn:model.lazy`).
    - Step 7: Observe if an alert box with the message "XSS Vulnerability" appears in the browser. If it does, the XSS vulnerability is confirmed, specifically when `safe` filter or `Meta.safe` is used without proper sanitization.
