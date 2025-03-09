### Vulnerability List

- Vulnerability Name: Django Model and QuerySet Serialization Information Disclosure
- Description: Django Unicorn automatically serializes Django Models and QuerySets that are bound to component fields using `unicorn:model`. When a component is rendered, all fields and values of these serialized objects are embedded directly into the HTML source code within `<script>` tags.  An attacker can simply inspect the page source to access this data. This unintended exposure of server-side data to the client can lead to sensitive information leakage.

    **Step-by-step trigger:**
    1. A developer creates a Django Unicorn component and defines a field that is a Django Model or QuerySet, e.g., `user = User.objects.first()`.
    2. In the component's template, the developer uses `unicorn:model` to bind an input or other HTML element to a field of this model, e.g., `<input type="text" unicorn:model="user.username">`.
    3. When the page containing this component is rendered on the server, Django Unicorn serializes the *entire* `user` object (including all fields, not just `username`) to JSON.
    4. This JSON data is embedded in the HTML source code within a `<script type="application/json" id="unicorn:data:{component_id}">` tag.
    5. An external attacker accesses the rendered page through a web browser.
    6. The attacker views the HTML source code of the page (e.g., by right-clicking and selecting "View Page Source" or using browser developer tools).
    7. The attacker locates the `<script>` tag with `id` starting with `unicorn:data:`.
    8. The JSON data within this `<script>` tag contains the full serialized representation of the Django Model or QuerySet, potentially including sensitive fields.

- Impact: High. Exposure of sensitive backend data. An external attacker can easily access sensitive information from Django models directly from the HTML source code. This can include personally identifiable information (PII), confidential business data, or internal system details, depending on the models exposed. This information can be used for identity theft, social engineering, or further attacks targeting the application or its users.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - Documentation explicitly warns about this behavior and recommends using `Meta.exclude` or `Meta.javascript_exclude` in the Unicorn component to prevent serialization of specific model fields.
    - Documentation suggests using `.values()` on QuerySets to select only specific fields intended for public view before assigning them to the component field.
- Missing Mitigations:
    - No default protection against automatic serialization of entire Django Models or QuerySets. The framework's default behavior is to serialize all model fields unless explicitly excluded by the developer.
    - No built-in mechanism to automatically sanitize or control the data being serialized. Developers must manually implement the suggested mitigations on a per-component basis.
- Preconditions:
    - Django Unicorn is installed and used in a Django project.
    - A Django Unicorn component is rendered in a template.
    - The component's view class defines a field that is a Django Model instance or QuerySet.
    - This Django Model or QuerySet field is bound to an HTML element in the component's template using `unicorn:model`.
- Source Code Analysis:
    - The vulnerability stems from the component rendering logic within `django_unicorn.components.unicorn_template_response.UnicornTemplateResponse.render` and `django_unicorn.views.__init__.py`, combined with how component attributes are handled in `django_unicorn.components.unicorn_view.UnicornView`.
    - When a component is rendered, `UnicornTemplateResponse.render` calls `self.get_context_data()` to gather data for the template.
    - `UnicornView.get_context_data()` in turn calls `self._attributes()` to retrieve all public attributes of the component instance.
    - `UnicornView._attributes()` effectively collects all public attributes of the component, including Django Models and QuerySets assigned to component fields.
    - `UnicornView.get_frontend_context_variables()` then serializes these attributes into a JSON string using `django_unicorn.serializer.dumps`. By default, `django.core.serializers.python.Serializer` is used, which serializes all model fields.
    - This serialized JSON data is embedded directly into the HTML within a `<script type="application/json" id="unicorn:data:{component_id}">` tag by `UnicornTemplateResponse.render`.
    - The code responsible for serialization is within `django_unicorn\components\unicorn_view.py` in the `get_frontend_context_variables` method:
        ```python
        def get_frontend_context_variables(self) -> str:
            """
            Get publicly available properties and output them in a string-encoded JSON object.
            """
            frontend_context_variables = {}
            attributes = self._attributes()
            frontend_context_variables.update(attributes)
            # ... (Meta.javascript_exclude handling) ...
            encoded_frontend_context_variables = serializer.dumps(
                frontend_context_variables,
                exclude_field_attributes=tuple(exclude_field_attributes),
            )
            return encoded_frontend_context_variables
        ```
    - The `serializer.dumps` function, without explicit field exclusion, will serialize the entire Django Model or QuerySet. The `Meta.javascript_exclude` is only applied *after* the attributes are collected and by default, it is empty, hence not excluding any fields unless explicitly configured in the component's Meta class.

- Security Test Case:
    1. Set up a Django project with Django Unicorn installed.
    2. Define a Django model named `SensitiveData` with fields like `public_field`, `secret_field_1`, and `secret_field_2`. Populate the database with at least one `SensitiveData` instance containing sensitive values in `secret_field_1` and `secret_field_2`.
    3. Create a Django Unicorn component named `SensitiveComponent`.
    4. In `SensitiveComponent`, define a field `data_object` of type `SensitiveData` and in the `mount` method, assign a `SensitiveData` instance fetched from the database to `self.data_object`.
        ```python
        # example\unicorn\components\sensitive.py
        from django_unicorn.components import UnicornView
        from example.app.models import SensitiveData

        class SensitiveComponentView(UnicornView):
            data_object: SensitiveData = None

            def mount(self):
                self.data_object = SensitiveData.objects.first()
        ```
    5. Create a template for `SensitiveComponent` (e.g., `sensitive.html`) and bind an input to a public field of `data_object` using `unicorn:model`.
        ```html
        <!-- example\unicorn\components\templates\sensitive.html -->
        <div>
            <input type="text" unicorn:model="data_object.public_field">
        </div>
        ```
    6. Create a Django template that includes the `SensitiveComponent`.
        ```html
        <!-- example\templates\sensitive_page.html -->
        {% load unicorn %}
        <!DOCTYPE html>
        <html>
        <head>
            <title>Sensitive Data Exposure Test</title>
            {% unicorn_scripts %}
        </head>
        <body>
            {% unicorn 'sensitive' %}
        </body>
        </html>
        ```
    7. Create a Django view to render `sensitive_page.html` and include it in `urls.py`.
    8. Run the Django development server and access the `sensitive_page` in a browser as an external attacker.
    9. View the HTML source code of the page.
    10. Search for the `<script type="application/json" id="unicorn:data:sensitivecomponent-...">` tag (the component id will vary).
    11. Within the JSON data in the `<script>` tag, verify that the entire `SensitiveData` object is serialized, including `secret_field_1` and `secret_field_2`, even though only `public_field` is used in the template with `unicorn:model`. This confirms the information disclosure vulnerability.
