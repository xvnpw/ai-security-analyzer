- Vulnerability Name: Cross-Site Scripting (XSS) due to Improper Output Encoding in Templates

- Description:
    - An attacker can inject malicious JavaScript code into component templates through user-controlled data.
    - This can be achieved by providing crafted input to fields bound by `unicorn:model` or arguments passed to component actions.
    - When the component re-renders, the injected JavaScript code is executed in the user's browser because the user-supplied data is not properly sanitized before being inserted into the HTML.

- Impact:
    - Execution of malicious JavaScript code in a user's browser.
    - This can lead to:
        - Account takeover by stealing cookies or session tokens.
        - Defacement of the web page.
        - Redirection to malicious websites.
        - Data theft, including sensitive user information.
        - Performing actions on behalf of the user without their consent.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - According to `changelog.md` version `0.36.0`, responses are HTML encoded to prevent XSS attacks. This mitigation is likely implemented in the code that serializes and sends component updates to the client.
    - File: `django_unicorn\changelog.md`
    - The `sanitize_html` function in `django_unicorn\utils.py` is used to escape HTML/XML special characters for JSON output, as seen in `django_unicorn\components\unicorn_template_response.py` within the `init_script` generation for `json_tag.string`.
    - File: `django_unicorn\django_unicorn\utils.py`
    - File: `django_unicorn\django_unicorn\components\unicorn_template_response.py`

- Missing Mitigations:
    - While HTML encoding is used in `init_script` for JSON data, it's not consistently applied across all user-supplied data rendered directly in component templates.
    - It's crucial to implement context-aware output encoding within the template rendering process itself to sanitize user-supplied data before it's inserted into the HTML.
    - Missing mitigations include:
        - Applying HTML entity encoding to variables rendered within HTML content in templates.
        - Using JavaScript encoding for variables inserted into JavaScript contexts within templates (if applicable).
        - Ensuring proper URL encoding for variables used in URLs within templates (if applicable).
    - The current `sanitize_html` function is focused on JSON output and is not applied to the general template rendering pipeline.

- Preconditions:
    - The application must use django-unicorn to render dynamic components based on user input.
    - An attacker needs to find an input field or action argument that is rendered unsafely in a component template.

- Source Code Analysis:
    - Analysis of the provided files in this batch (`test_construct_model.py`, `test_set_property_from_data.py`, `pyproject.toml`):
        - `test_construct_model.py`: Contains tests for the `_construct_model` function, which is responsible for creating model instances from dictionaries. This file does not contain any code related to security or XSS mitigation. It focuses on testing the correct construction of Django models, including handling foreign keys and many-to-many relationships.
        - `test_set_property_from_data.py`: Includes tests for the `set_property_from_data` function, which sets properties on a component instance based on data received from the client.  These tests cover various data types, including strings, integers, datetimes, lists, models, and querysets. While this function handles user-provided data, the tests do not show any built-in sanitization or encoding being applied to the data before it's set as a component property. The focus is on data type conversion and handling different property types.
        - `pyproject.toml`: This file is the project configuration file, defining dependencies, development tools, and build settings. It does not contain any application code or security-related configurations relevant to XSS mitigation.
        - **None of the files in this batch introduce new security mitigations for XSS in template rendering, nor do they fundamentally alter the understanding of the existing vulnerability.** The tests in `test_set_property_from_data.py` indirectly reinforce the potential for XSS, as they demonstrate how user-provided data is directly used to update component properties without any visible sanitization step in these tests. This data can then be rendered in templates, leading to the identified XSS vulnerability if not properly handled in the template rendering process.

- Security Test Case:
    1. Deploy a Django application with django-unicorn library installed.
    2. Create a django-unicorn component that renders user-supplied data from a `unicorn:model` binding directly into the HTML template without any additional HTML encoding.
        - Example Component Template (`xss_component.html`):
          ```html
          <div>
              <input type="text" unicorn:model="userInput">
              <div id="output">Raw Output: {{ userInput }}</div>
              <div id="safeOutput">Safe Output: {{ userInput|escape }}</div>
          </div>
          ```
        - Example Component View (`xss_component.py`):
          ```python
          from django_unicorn.components import UnicornView

          class XSSComponentView(UnicornView):
              userInput = ""
          ```
    3. In a Django template, include the `xss_component`.
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
    4. Access the page in a web browser.
    5. In the input field of the component, enter a XSS payload, for example: `<img src=x onerror="alert('XSS Unsafe')">`.
    6. Interact with the component to trigger a re-render (e.g., type in the input field and blur or trigger an action).
    7. Observe the output in the browser:
        - If an alert box with "XSS Unsafe" appears next to "Raw Output:", it indicates that the raw output is vulnerable to XSS.
        - If the payload is rendered as plain text (e.g., `&lt;img src=x onerror=&quot;alert('XSS')&gt;`) next to "Safe Output:", it indicates that using the `escape` filter mitigates XSS in this specific template location, highlighting the need for developers to manually apply proper escaping.
    8. Repeat steps 5-7 with different XSS payloads and in different contexts (e.g., within HTML attributes, JavaScript event handlers if applicable) to comprehensively test for XSS vulnerabilities in various template locations and with different input contexts.
    9. If the "XSS Unsafe" alert appears, it confirms the vulnerability in the raw output context. This demonstrates that while there are some mitigations in place for JSON data in `<script>` tags, dynamic content rendered directly in templates from user input is still potentially vulnerable if developers do not manually apply output escaping.
