### Vulnerability List for django-unicorn Project

* Vulnerability Name: Sensitive Information Disclosure via Django Model Serialization

* Description:
    1. A developer uses Django Unicorn and includes a Django model as a public class variable in a Unicorn component view.
    2. The Django Unicorn framework, by default, serializes all public attributes of the component view, including the Django model instance, into JSON.
    3. This serialized JSON data is embedded in the HTML source code of the rendered component, specifically within a `<script type="application/json" id="unicorn:data:{component_id}">` tag.
    4. An external attacker can view the HTML source code of the page.
    5. The attacker can extract the serialized JSON data containing the Django model instance.
    6. If the Django model instance contains sensitive information (e.g., personal data, internal IDs, configuration values not intended for public exposure), this information is now disclosed to the attacker.
    7. This occurs because the default serialization includes all fields of the Django model, potentially exposing data that should remain server-side.

* Impact:
    Exposure of sensitive information contained within Django models to unauthorized external attackers. This could include personal data, business-critical information, or internal application details, depending on the model and its fields. The impact severity depends on the sensitivity of the disclosed data and the context of the application. In many cases, unauthorized disclosure of personal or confidential business data is considered a high-severity vulnerability.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - **`Meta.javascript_exclude`**:  The documentation mentions the `Meta.javascript_exclude` option within the Unicorn view. This allows developers to explicitly exclude specific attributes from being serialized and included in the JavaScript data.
    - **`Meta.exclude`**: The documentation also describes `Meta.exclude` which prevents attributes from being available in the component template and Javascript.
    - **Custom Serialization (to_json method)**: Developers can define a `to_json` method on custom classes or models to control how they are serialized, allowing them to selectively include only non-sensitive data.

* Missing Mitigations:
    - **Default to excluding all model fields**: By default, Django Unicorn could avoid serializing Django model fields unless explicitly included using an `include` Meta option (opposite of `exclude`). This would enforce a secure-by-default behavior.
    - **Clear warning in documentation**: The documentation *mentions* the warning, but it should be made more prominent and explicitly list the risks of default model serialization.

* Preconditions:
    1. A Django Unicorn component view includes a Django model instance as a public class variable.
    2. The component is rendered in a publicly accessible template.
    3. The developer does not implement any of the provided mitigations (e.g., `Meta.javascript_exclude`, `Meta.exclude`, custom `to_json`).

* Source Code Analysis:
    Based on the documentation ("Views" section) and code analysis of `django_unicorn/serializer.py` and `django_unicorn/components/unicorn_view.py`, the following is confirmed:
    1. `django_unicorn/serializer.py` contains `_get_model_dict` function which serializes Django models using Django's built-in serializer and `orjson`.
    ```python
    def _get_model_dict(model: Model) -> dict:
        """
        Serializes Django models. Uses the built-in Django JSON serializer, but moves the data around to
        remove some unnecessary information and make the structure more compact.
        """
        # ...
        serialized_model = serialize("json", [model])[1:-1]
        # ...
        model_json = orjson.loads(serialized_model)
        model_json = model_json.get("fields")
        model_json["pk"] = model_pk
        # ...
        return model_json
    ```
    This function, by default, extracts all 'fields' from the Django model during serialization.
    2. `django_unicorn/components/unicorn_view.py` in `get_frontend_context_variables()` method iterates through component attributes and serializes them.
    ```python
    def get_frontend_context_variables(self) -> str:
        """
        Get publicly available properties and output them in a string-encoded JSON object.
        """
        frontend_context_variables = {}
        attributes = self._attributes() # calls _attributes() which uses _attribute_names() to get public attributes
        frontend_context_variables.update(attributes)
        # ...
        encoded_frontend_context_variables = serializer.dumps(
            frontend_context_variables,
            exclude_field_attributes=tuple(exclude_field_attributes),
        )
        return encoded_frontend_context_variables
    ```
    The `_attributes()` and `_attribute_names()` methods (also in `django_unicorn/components/unicorn_view.py`) are used to determine publicly available attributes of the component, which by default includes Django model instances if they are public class variables.
    3. By default, there is no explicit filtering of model fields during serialization within `_get_model_dict` or `get_frontend_context_variables` unless `Meta.javascript_exclude` or `Meta.exclude` is used in the Unicorn component.
    4. The documentation (as mentioned in previous analysis) warns about this behavior and suggests using `javascript_exclude`.

* Security Test Case:
    1. Create a Django project with Django Unicorn installed.
    2. Define a Django model named `UserProfile` with fields `username`, `email`, and `secret_api_key`. Mark `secret_api_key` as containing sensitive information.
    ```python
    # example/coffee/models.py
    from django.db import models

    class UserProfile(models.Model):
        username = models.CharField(max_length=255)
        email = models.EmailField()
        secret_api_key = models.CharField(max_length=255) # Sensitive field
    ```
    3. Create a Unicorn component view `UserProfileComponentView`.
    ```python
    # example/unicorn/components/user_profile.py
    from django_unicorn.components import UnicornView
    from example.coffee.models import UserProfile

    class UserProfileComponentView(UnicornView):
        template_name = "unicorn/user-profile.html" # or define template_html

        user_profile = None

        def mount(self):
            self.user_profile = UserProfile.objects.first() # Assumes there is at least one UserProfile in DB
    ```
    4. In `UserProfileComponentView`, create a public class variable `user_profile` and assign it an instance of `UserProfile` (e.g., `user_profile = UserProfile.objects.first()`).
    5. In the component's template (`unicorn/user-profile.html`), simply render the component: `<div></div>`. No need to display any data in the template itself to demonstrate the vulnerability.
    ```html
    # example/unicorn/templates/unicorn/user-profile.html
    <div></div>
    ```
    6. Create a Django view that renders a template (`test_template.html`) which includes the `UserProfileComponentView` using `{% unicorn 'user-profile' %}`.
    ```python
    # example/www/views.py
    from django.shortcuts import render

    def test_view(request):
        return render(request, 'www/test_template.html')

    # example/www/urls.py
    from django.urls import path
    from example.www import views

    urlpatterns = [
        path('test-sensitive-data', views.test_view, name='test_sensitive_data'),
    ]
    ```
    ```html
    # example/www/templates/www/test_template.html
    {% load unicorn %}
    <!DOCTYPE html>
    <html>
    <head>
        <title>Sensitive Data Test</title>
    </head>
    <body>
        {% unicorn 'user-profile' %}
        {% unicorn_scripts %}
    </body>
    </html>
    ```
    7. Access the Django view in a web browser as an external attacker (e.g., `/test-sensitive-data`).
    8. Inspect the HTML source code of the rendered page.
    9. Search for a `<script type="application/json" id="unicorn:data:user-profile-{unique_id}">` tag.
    10. Within the JSON data in the script tag, verify that all fields from the `UserProfile` model are present, including the `secret_api_key` and its value, even though it was not explicitly used or rendered in the template.
    ```html
    <script type="application/json" id="unicorn:data:user-profile-abcd123">
    {
        "user_profile": {
            "pk": 1,
            "username": "testuser",
            "email": "test@example.com",
            "secret_api_key": "sensitive_value"
        },
        // ... other component data
    }
    </script>
    ```
    This test case will confirm that the `secret_api_key` is exposed in the HTML source code, demonstrating the sensitive information disclosure vulnerability.

---
