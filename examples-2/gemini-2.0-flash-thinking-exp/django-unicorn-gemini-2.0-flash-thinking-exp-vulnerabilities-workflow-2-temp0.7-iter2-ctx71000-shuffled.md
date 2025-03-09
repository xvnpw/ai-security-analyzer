## Vulnerability List

### 1. Unsafe HTML rendering using `safe` Meta option

* Description:
    1. A developer uses the `safe` Meta option in a django-unicorn component's `Meta` class to prevent HTML encoding for a specific property.
    2. This property is used in the component's template to render user-controlled data, such as data bound using `unicorn:model` or passed as arguments to the component.
    3. The developer fails to sanitize this user-controlled data before rendering it in the template.
    4. An attacker can inject malicious Javascript code into the user-controlled data.
    5. When the component updates and re-renders (e.g., after a user interaction or model update), the injected Javascript code is rendered without HTML encoding and executed in the user's browser.
* Impact: Cross-Site Scripting (XSS). An attacker can execute arbitrary Javascript code in the context of the user's browser. This can lead to session hijacking, cookie theft, defacement of the web page, or redirection to malicious websites.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - By default, django-unicorn automatically HTML-encodes all component properties before rendering them in the template. This behavior is described in `docs\source\views.md` and confirmed by the changelog entry for version 0.36.0 in `docs\source\changelog.md`, which mentions a security fix (CVE-2021-42053) to prevent XSS attacks by ensuring default HTML encoding.
* Missing Mitigations:
    - While default HTML encoding is a strong mitigation, the `safe` Meta option allows developers to explicitly disable this protection. The documentation (`docs\source\views.md`) explains the `safe` option but lacks sufficient security warnings about its use, especially when rendering user-controlled data. There are no explicit warnings against using `safe` without careful sanitization of user inputs in the documentation for the `safe` option in `docs\source\views.md`.
* Preconditions:
    1. The developer must explicitly use the `safe` Meta option in the component's Python view for a specific property.
    2. This property must be used to render user-controlled data in the component's HTML template.
    3. The developer must not sanitize or escape the user-controlled data before rendering it when the `safe` option is enabled.
* Source Code Analysis:
    - `docs\source\views.md`: As previously analyzed, this file documents the `safe` Meta option, explaining that it disables default HTML encoding.
    - `docs\source\changelog.md`: Confirms that HTML encoding is the default behavior as a security measure against XSS, and the `safe` option is provided to opt-out of this default encoding.
    - `django_unicorn\components\unicorn_view.py`: The `get_frontend_context_variables` method prepares data for the frontend. While default encoding is not explicitly visible here, it's implied to be handled during template rendering by Django's template engine, which is bypassed by the `safe` option. The code iterates through `safe_fields` and uses `mark_safe` in `django_unicorn\views\__init__.py` within the `_process_component_request` function, specifically in the lines:
        ```python
        # Mark safe attributes as such before rendering
        for field_name in safe_fields:
            value = getattr(component, field_name)
            if isinstance(value, str):
                setattr(component, field_name, mark_safe(value))  # noqa: S308
        ```
        This code marks the Python variable as safe, but the template rendering process, especially when `safe` is used, will directly render this "safe" content without further encoding, leading to potential XSS if the content is user-controlled and contains malicious script.
    - `django_unicorn\templatetags\unicorn.py`: The `unicorn` template tag is responsible for rendering the component. It does not include any explicit HTML sanitization logic for component properties. When the template engine renders the component's template, and if a property marked as `safe` is used, it will render the raw, unsanitized content.
    - `django_unicorn\django_unicorn\components\unicorn_template_response.py`: This file handles the overall template response but delegates the actual rendering to Django's template engine. It includes `sanitize_html` for the component initialization data within the `<script>` tag, but this is separate from the template rendering of component properties. The `_desoupify` method in `UnicornTemplateResponse` uses `BeautifulSoup` to process the rendered HTML, but this is for manipulating the HTML structure (adding attributes, scripts), not for sanitizing the content rendered from component properties within the templates.
* Security Test Case:
    1. Create a new django-unicorn component named `xss_test`.
    2. In `xss_test/components/xss_test.py`, define a component view like this:
    ```python
    from django_unicorn.components import UnicornView

    class XssTestView(UnicornView):
        unsafe_data = ""

        class Meta:
            safe = ("unsafe_data",)
    ```
    3. In `xss_test/templates/unicorn/xss_test.html`, create the component template:
    ```html
    <div>
        <input type="text" unicorn:model="unsafe_data" id="input-field">
        <div id="output-area">{{ unsafe_data }}</div>
    </div>
    ```
    4. Create a Django template (e.g., `test_page.html`) to include the `xss_test` component:
    ```html
    {% load unicorn %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        {% unicorn 'xss-test' %}
    </body>
    </html>
    ```
    5. Set up a Django view to render `test_page.html` and include `django_unicorn` in `INSTALLED_APPS` and `urls.py` as described in the django-unicorn documentation.
    6. Access `test_page.html` in a web browser.
    7. In the input field (identified by `input-field`), enter the following malicious payload: `<img src=x onerror=alert('XSS Vulnerability')>`.
    8. Click outside the input field or trigger an update to the component (e.g., by adding a button with an action).
    9. Observe that an alert box with the message "XSS Vulnerability" pops up in the browser. This confirms that the Javascript code injected through the input field was executed because the `unsafe_data` was rendered without proper HTML encoding due to the `safe` Meta option, resulting in a Cross-Site Scripting vulnerability.

### 2. Uncontrolled Attribute Modification via `set_property_from_data`

* Description:
    1. An attacker can send a crafted AJAX request to the Django Unicorn backend.
    2. This request includes `data` that specifies a property name to be updated on a Unicorn component.
    3. The `set_property_from_data` function in `django_unicorn/views/utils.py` is used to set the component's property.
    4. Due to insufficient input validation in `set_property_from_data`, an attacker can potentially modify arbitrary attributes of the Unicorn component, including those not intended for client-side modification.
    5. This is possible because the `set_property_from_data` function checks for the existence of an attribute using `hasattr` but does not validate if the attribute is meant to be mutable from the client or if it's an internal attribute.
    6. By sending a malicious request with a crafted property name, an attacker can overwrite internal component state, potentially leading to unexpected behavior or security vulnerabilities.
* Impact:
    - **High**: Arbitrary modification of component attributes can lead to a wide range of issues. Depending on the attribute modified, this could potentially lead to:
        - Logic bypass: Modifying internal flags or counters could bypass intended component logic.
        - Data manipulation: Overwriting data attributes could lead to incorrect data being displayed or processed.
        - Unexpected behavior: Changing internal state might cause the component to malfunction or behave in unpredictable ways.
        - In certain scenarios, if an attacker can modify attributes that control access or permissions, it might escalate to more severe vulnerabilities.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - **Checksum Validation**: Django Unicorn implements checksum validation to ensure the integrity of the data sent from the client. This prevents tampering with the entire data payload but does not prevent targeting specific attributes within the valid payload. Implemented in `ComponentRequest.validate_checksum` in `django_unicorn/views/objects.py`.
    - **Type Hinting and Casting**: Django Unicorn uses type hints and casting to convert client-provided values to the expected Python types. This can prevent some basic injection attempts by enforcing data type constraints. Implemented in `set_property_from_data` and `cast_value` in `django_unicorn/typer.py`.
* Missing Mitigations:
    - **Attribute Allowlist/Blocklist**: A mechanism to define which component attributes are allowed to be modified from the client-side. This could be implemented as an allowlist of mutable properties or a blocklist of protected properties.
    - **Input Validation for Property Names**:  Explicit validation of the property names received from the client to ensure they are within the expected set of mutable properties.
* Preconditions:
    - The attacker needs to know the name of an attribute within a Unicorn component. This information might be obtained through source code analysis or by observing component behavior.
    - The target attribute must be modifiable via `setattr` in Python, meaning it shouldn't be a read-only property or descriptor that prevents setting.
* Source Code Analysis:
    1. **File:** `django_unicorn/views/utils.py`
    2. **Function:** `set_property_from_data(component_or_field, name, value)`
    3. **Code Snippet:**
       ```python
       def set_property_from_data(
           component_or_field: Union[UnicornView, UnicornField, Model],
           name: str,
           value: Any,
       ) -> None:
           """
           Sets properties on the component based on passed-in data.
           """

           try:
               if not hasattr(component_or_field, name): # [1] Check if attribute exists
                   return
           except ValueError:
               # Treat ValueError the same as a missing field ...
               return

           field = getattr(component_or_field, name) # [2] Get attribute

           # ... (rest of the logic for handling UnicornField, Model, etc.) ...

           elif hasattr(field, "related_val"):
               # ...
           else:
               # ...
               if hasattr(component_or_field, "_set_property"):
                   # Can assume that `component_or_field` is a component
                   component_or_field._set_property(name, value, call_updating_method=True, call_updated_method=False) # [3] Set property using _set_property if available
               else:
                   setattr(component_or_field, name, value) # [4] Otherwise, set attribute directly using setattr
       ```
    4. **Vulnerability Point:** Lines [3] and [4] demonstrate how the attribute is ultimately set. The code first checks if the attribute exists using `hasattr` [1] and retrieves it using `getattr` [2]. However, there's no validation to ensure that setting this attribute is intended or safe from a security perspective. It blindly sets the attribute using either `_set_property` (if available) or `setattr` [4].
    5. **Attack Vector:** An attacker can craft a JSON payload in the AJAX request to the `message` endpoint, specifying a `name` that corresponds to a component attribute they wish to modify. If the component processes this request, `set_property_from_data` will attempt to set the attribute with the attacker-provided `value`.
* Security Test Case:
    1. **Create a vulnerable component:**
       ```python
       # tests/views/fake_components.py
       from django_unicorn.components import UnicornView

       class VulnerableComponent(UnicornView):
           template_name = "templates/test_component.html"
           internal_state = "initial" # Define an internal state variable

           def get_internal_state(self):
               return self.internal_state
       ```
       ```html
       {# templates/test_component.html #}
       <div>
           <span id="internal-state">{{ internal_state }}</span>
       </div>
       ```

    2. **Render the component in a test view:**
       ```python
       # tests/views/message/test_uncontrolled_attribute.py
       from tests.views.message.utils import post_and_get_response
       from tests.views.fake_components import VulnerableComponent

       VULNERABLE_COMPONENT_URL = "/message/tests.views.fake_components.VulnerableComponent"

       def test_uncontrolled_attribute_modification(client):
           # Initial render to get component ID and initial state
           response = client.get(VULNERABLE_COMPONENT_URL)
           assert response.status_code == 200
           assert "initial" in response.content.decode()

           # Craft a malicious request to modify 'internal_state'
           data = {"internal_state": "modified_by_attacker"}
           action_queue = [] # No actions needed, just data sync

           response_json = post_and_get_response(
               client,
               url=VULNERABLE_COMPONENT_URL,
               data=data,
               action_queue=action_queue,
           )

           # Re-render the component to check if 'internal_state' is modified
           response = client.get(VULNERABLE_COMPONENT_URL)
           assert response.status_code == 200
           assert "modified_by_attacker" in response.content.decode() # Verify state is modified

       ```

    3. **Run the test:** Execute the test `test_uncontrolled_attribute_modification`. If the test passes and the rendered content shows "modified_by_attacker", it confirms the vulnerability.
