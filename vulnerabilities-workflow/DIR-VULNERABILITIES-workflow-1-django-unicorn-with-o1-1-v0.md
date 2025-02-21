### Reflected Cross-Site Scripting (XSS) via Unsafe String Rendering

* Description
    * An attacker can inject arbitrary HTML or JavaScript code into the component's template by manipulating component properties that are rendered as "safe" in the template. This is possible when a component uses `Meta.safe` or the `|safe` template filter to render a string property without proper sanitization, and this property is influenced by user input via actions or model updates.
    * Step-by-step trigger:
        1. Create a Django Unicorn component with a string property, e.g., `unsafe_string`.
        2. In the component's template, render this property using either `{{ unsafe_string|safe }}` or by including `unsafe_string` in `Meta.safe`.
        3. Create an action in the component that allows setting the `unsafe_string` property based on user input. For example, an input field bound to `unsafe_string` with `unicorn:model`.
        4. An attacker crafts a malicious string containing JavaScript code, e.g., `<img src=x onerror=alert('XSS')>`.
        5. The attacker inputs this malicious string into the input field, triggering the action and updating the `unsafe_string` property.
        6. The component re-renders, and the malicious string is inserted into the DOM without proper escaping because of `|safe` filter or `Meta.safe` setting.
        7. The JavaScript code in the malicious string executes in the user's browser, leading to XSS.

* Impact
    * High
    * Successful exploitation allows an attacker to execute arbitrary JavaScript code in the victim's browser when they view the page containing the vulnerable component. This can lead to:
        - Account Takeover: Stealing session cookies or credentials to impersonate the user.
        - Data Theft: Accessing sensitive information visible to the user.
        - Defacement: Modifying the content of the web page seen by the user.
        - Redirection: Redirecting the user to malicious websites.
        - Further Attacks: Using the compromised user session to perform actions on behalf of the user.

* Vulnerability Rank
    * High

* Currently implemented mitigations
    * By default, Django Unicorn HTML encodes updated field values to prevent XSS attacks since version 0.36.0. This is a global mitigation that applies to all rendered component properties unless explicitly marked as safe.

* Missing mitigations
    * Project lacks specific sanitization functions for user inputs that are intended to be rendered as safe HTML.
    * No clear guidance in documentation to developers about the risks of using `|safe` filter or `Meta.safe` and best practices for sanitizing user-provided content before rendering it as safe HTML.

* Preconditions
    * Developer must explicitly use `|safe` filter in the template or include the property in `Meta.safe` in the component view.
    * A component property rendered as safe HTML must be directly or indirectly controllable by user input.

* Source code analysis
    1. **`django_unicorn/views.py`**: The `UnicornView.render` method and template rendering process are responsible for rendering component templates.
    2. **`django_unicorn/serializer.py`**: The `dumps` function serializes component data to JSON for sending to the frontend. While serialization itself is safe, it's the rendering of "safe" properties in templates that creates the vulnerability.
    3. **Template files (`*.html`)**: If a template uses `{{ component.unsafe_string|safe }}` or if `unsafe_string` is in `Meta.safe`, the output will not be escaped.
    4. **Example vulnerable code:**

        ```python
        # components/unsafe_component.py
        from django_unicorn.components import UnicornView

        class UnsafeComponentView(UnicornView):
            unsafe_string = ""

            class Meta:
                safe = ("unsafe_string",) # or remove this and use |safe in template

            def set_unsafe_string(self, value):
                self.unsafe_string = value
        ```

        ```html
        {# templates/unicorn/unsafe_component.html #}
        <div>
            <input type="text" unicorn:model.defer="unsafe_string">
            <button unicorn:click="set_unsafe_string(unsafe_string)">Set Unsafe String</button>
            <div id="unsafe-render">
                {{ unsafe_string }} {# Vulnerable if Meta.safe is set or |safe filter is used #}
            </div>
        </div>
        ```

* Security test case
    1. Create a vulnerable Django Unicorn component as described in the source code analysis.
    2. Deploy the Django application with the vulnerable component to a publicly accessible instance.
    3. As an attacker, access the page containing the vulnerable component.
    4. In the input field, enter the following payload: `<img src=x onerror=alert('XSS-Unicorn')>`.
    5. Click the button to trigger the `set_unsafe_string` action.
    6. Observe that an alert box with 'XSS-Unicorn' is displayed in the browser, demonstrating successful XSS exploitation.
    7. Inspect the HTML source code and confirm that the malicious payload is rendered directly within the `div#unsafe-render` element without HTML escaping.
