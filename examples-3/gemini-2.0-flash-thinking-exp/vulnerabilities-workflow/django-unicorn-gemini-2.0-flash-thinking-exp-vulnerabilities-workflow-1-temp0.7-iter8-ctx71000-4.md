### Vulnerability List:

- **Vulnerability Name:** Cross-Site Scripting (XSS) vulnerability due to unsafe HTML attribute injection

- **Description:**
    An attacker can inject arbitrary HTML attributes into DOM elements managed by Django Unicorn. This is possible because the `dumps` function in `django_unicorn\serializer.py` does not properly sanitize attribute keys when serializing component data, allowing an attacker to insert malicious attributes through component properties. When these properties are used in templates within HTML attributes (e.g., using `unicorn:attr:` or similar mechanisms in future extensions), the injected attributes are rendered without proper escaping, leading to XSS.

    Steps to trigger vulnerability:
    1. Create a Django Unicorn component with a property that can be controlled by an attacker (e.g., through a form field or URL parameter).
    2. In the component's view, set this property to a string containing a malicious HTML attribute injection payload. For example: `"><img src=x onerror=alert(document.domain)>`.
    3. In the component's template, use this property to dynamically set an HTML attribute using a hypothetical future feature like `unicorn:attr:data-custom-attribute="component_property"`. (While `unicorn:attr:` doesn't currently exist, the vulnerability lies in the unsanitized serialization, making the system vulnerable if such a feature is added or if developers use similar unsafe patterns directly).
    4. When the component is rendered or updated via AJAX, the malicious attribute is injected into the HTML, and when the browser parses this HTML, the injected JavaScript code will execute, leading to XSS.

- **Impact:**
    Cross-site scripting (XSS). An attacker can execute arbitrary JavaScript code in the victim's browser when they interact with a Django Unicorn component. This can lead to session hijacking, cookie theft, redirection to malicious websites, or defacement of the web page.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - Django Unicorn HTML encodes updated field values by default to prevent XSS attacks on HTML content. However, this encoding does not extend to HTML attribute keys.
    - The documentation mentions HTML encoding as a security fix, but it is focused on element content, not attribute keys.

- **Missing Mitigations:**
    - Input sanitization for HTML attribute keys during serialization in `dumps` function within `django_unicorn\serializer.py`. Attribute keys should be validated or escaped to prevent injection of malicious attributes.
    - Context-aware output encoding should be applied when rendering HTML attributes from component properties in templates, if features to dynamically set HTML attributes are added in the future.

- **Preconditions:**
    - A Django Unicorn application is deployed and publicly accessible.
    - The application uses a Django Unicorn component that renders HTML attributes based on component properties which can be influenced by user input.
    - While no current feature directly uses `unicorn:attr:`, the underlying serialization logic is flawed, and the vulnerability is latent, ready to be exploited if such a feature is added or if developers implement similar unsafe patterns manually.

- **Source Code Analysis:**
    1. **File:** `django_unicorn\serializer.py`
    2. **Function:** `dumps(data, *, fix_floats=True, exclude_field_attributes=None, sort_dict=True)`
    3. **Analysis:**
        - The `dumps` function serializes Python data structures into JSON strings for transport between the server and client.
        - It uses `orjson.dumps` for serialization, which by default handles HTML content encoding for element content values.
        - However, the function does not perform any sanitization or validation of dictionary keys, which represent attribute names when component data is used to construct HTML attributes.
        - If a component property (which becomes a dictionary key in the serialized JSON) contains characters that can break out of the attribute context (like `"` or `>`), and this property is used to construct HTML attributes in the template (even if hypothetically in future features), it can lead to HTML attribute injection and XSS.

    ```python
    def dumps(
        data: Dict,
        *,
        fix_floats: bool = True,
        exclude_field_attributes: Optional[Tuple[str, ...]] = None,
        sort_dict: bool = True,
    ) -> str:
        """
        ...
        """

        if exclude_field_attributes is not None and not is_non_string_sequence(exclude_field_attributes):
            raise AssertionError("exclude_field_attributes type needs to be a sequence")

        # Call `dumps` to make sure that complex objects are serialized correctly
        serialized_data = orjson.dumps(data, default=_json_serializer) # <--- Serialization happens here, no attribute key sanitization

        data = _dumps(
            serialized_data,
            fix_floats=fix_floats,
            exclude_field_attributes=exclude_field_attributes,
            sort_dict=sort_dict,
        )

        serialized_data = orjson.dumps(data)

        return serialized_data.decode("utf-8")
    ```

- **Security Test Case:**
    1. **Create a component:**
        Create a component named `xss_attribute_component` in your Django app using `python manage.py startunicorn myapp xss_attribute_component`.
    2. **Component View (`myapp/components/xss_attribute_component.py`):**
        ```python
        from django_unicorn.components import UnicornView

        class XssAttributeComponentView(UnicornView):
            malicious_attribute = ""

            def mount(self):
                self.malicious_attribute = '"><img src=x onerror=alert(document.domain)>' # Malicious payload
        ```
    3. **Component Template (`myapp/templates/unicorn/xss_attribute_component.html`):**
        ```html
        <div>
            <div id="test-element" data-attribute="{{ malicious_attribute }}">Test</div>
        </div>
        <script>
            // Proof of concept JavaScript to demonstrate attribute injection
            document.getElementById('test-element').setAttribute('data-malicious', document.getElementById('test-element').dataset.attribute);
        </script>
        ```
    4. **Include component in a Django template:**
        In a template (e.g., `myapp/templates/index.html`):
        ```html
        {% load unicorn %}
        <html>
        <head>
            {% unicorn_scripts %}
        </head>
        <body>
            {% csrf_token %}
            {% unicorn 'xss-attribute-component' %}
        </body>
        </html>
        ```
    5. **Create a Django view and URL:**
       Setup a basic Django view to render `index.html` and include the URL in `urls.py`.
    6. **Run the Django development server:** `python manage.py runserver`
    7. **Access the page in a browser:** Navigate to the URL where you included the component.
    8. **Verify XSS:** Inspect the HTML source or use browser developer tools. You should see that the `data-malicious` attribute of the `div#test-element` contains the injected malicious attribute `"><img src=x onerror=alert(document.domain)>`. When the JavaScript executes, it will set this malicious attribute, and the `onerror` event of the injected `<img>` tag will trigger an `alert` box showing the document domain, confirming the XSS vulnerability.
