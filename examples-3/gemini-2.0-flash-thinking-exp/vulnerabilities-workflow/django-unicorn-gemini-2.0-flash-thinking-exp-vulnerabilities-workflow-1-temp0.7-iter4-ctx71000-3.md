## Vulnerability List for django-unicorn project

**Current Vulnerabilities:**

- Potential Mass Assignment in Model Updates via QuerySets
    - Description:
        1. A developer creates a Django Unicorn component that exposes a Django model queryset as a public property with a type hint `QuerySetType[SomeModel]`.
        2. The component's template allows users to modify data associated with the model instances in the queryset.
        3. When the user interacts with the component to update model data, the frontend sends a request to the backend with updated data for the queryset as a list of dictionaries.
        4. The `create_queryset` function in `django_unicorn\typer.py` and `_construct_model` are used to update the queryset based on the received data.
        5. If the Django model `SomeModel` has fields that should not be directly updated by users (e.g., audit fields, permissions fields, etc.) and these are not protected by Django's built-in mechanisms, an attacker can potentially modify these fields by including them in the update data sent from the frontend.
    - Impact: Unauthorized modification of sensitive model fields. Depending on the model and fields, this could lead to data corruption, privilege escalation, or other security breaches.
    - Vulnerability Rank: high
    - Currently implemented mitigations: None in the `django-unicorn` project itself to prevent mass assignment in model updates via QuerySets. Django's model layer provides some protection (e.g., `editable=False` fields are generally not updatable via forms), but it's not enforced by `django-unicorn`.
    - Missing mitigations:
        - Input validation and sanitization specifically for model updates, especially when handling QuerySets.
        - Option for developers to specify which fields are allowed to be updated via frontend requests for model properties.
        - Documentation highlighting the risk of exposing mutable QuerySets and the importance of model-level and form-level validation and protection against mass assignment.
    - Preconditions:
        - A Django Unicorn component exposes a `QuerySetType[SomeModel]` property.
        - The component's template allows users to modify and submit data related to the model instances in the queryset.
        - The Django model `SomeModel` has fields that should not be directly user-updatable and are not adequately protected.
    - Source code analysis:
        1. File: `django_unicorn\typer.py`
            - Function: `create_queryset(obj, type_hint, value)`
            - Function: `_construct_model(model_type, model_data: Dict)`
            - Vulnerability: Inside `_construct_model`, it iterates through `model_data.keys()` and sets attributes using `setattr(model, column_name, model_data[field_name])` without explicit checks to prevent setting arbitrary fields. The function `cast_value` (tested in `test_typer.py`) is used within `_construct_model` to handle different data types, but it does not perform field-level validation to prevent mass assignment.
            ```python
            def _construct_model(model_type, model_data: Dict):
                """Construct a model based on the type and dictionary data."""
                # ...
                for field_name in model_data.keys():
                    for field in model._meta.fields:
                        if field.name == field_name or (field_name == "pk" and field.primary_key):
                            column_name = field.name
                            # ...
                            setattr(model, column_name, model_data[field_name])
                            break
                return model
            ```
        2. File: `django_unicorn\views\utils.py`
            - Function: `set_property_from_data(component_or_field: Union[UnicornView, UnicornField, Model], name: str, value: Any)`
            - Vulnerability: Calls `create_queryset` if the property is a queryset. This function is the entry point for setting component properties based on data from the frontend, and when it encounters a queryset, it uses the vulnerable `create_queryset` path.
            ```python
            def set_property_from_data(component_or_field, name, value):
                # ...
                if is_queryset(field, type_hint, value):
                    value = create_queryset(field, type_hint, value)
                # ...
            ```
        3. File: `django_unicorn\views\__init__.py`
            - Function: `_process_component_request`
            - Vulnerability: Calls `set_property_from_data` to update component properties based on request data. This function is the main handler for processing frontend requests and updating the component state, which can trigger the vulnerable queryset update path through `set_property_from_data`.
    - Security test case:
        1. Create a Django model `UserProfile` with fields: `username`, `email`, `is_staff`, `last_login`. Do not set `editable=False` for `is_staff` and `last_login`.
        2. Create a Django Unicorn component `UserProfilesComponent` with:
            ```python
            from django_unicorn import QuerySetType, UnicornView
            from .models import UserProfile  # Replace with your actual model import

            class UserProfilesComponentView(UnicornView):
                user_profiles: QuerySetType[UserProfile] = UserProfile.objects.all()
            ```
        3. Create a template for `UserProfilesComponent` that displays a list of user profiles and allows updating `username` and `email`.
        4. As an attacker, using browser's developer tools, intercept the request when updating a user profile.
        5. Modify the request payload to include `is_staff: true` and `last_login: "2023-01-01T00:00:00Z"` for a target user profile.
        6. Send the modified request.
        7. Verify in the Django admin panel or database directly that the `is_staff` and `last_login` fields of the target user profile have been updated.
