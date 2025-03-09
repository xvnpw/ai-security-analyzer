# VULNERABILITIES

## Unauthorized Method Execution (High)

### Description
Django-Unicorn allows calling component methods from the frontend through AJAX requests. The framework processes these requests in the backend, allowing methods to be called on Python components based on frontend input. While the framework uses AST parsing for method name extraction (which is safer than using `eval()`), there appears to be no validation mechanism to restrict which methods can be called. This allows potential attackers to call any public method on a component, including those that were not intended to be exposed to the frontend.

### Impact
An attacker who can access the frontend application could potentially invoke sensitive methods that perform critical operations such as data deletion, privilege escalation, or accessing sensitive information, even if these methods were not intended to be called from the client side.

### Currently Implemented Mitigations
The framework includes CSRF protection which prevents cross-site request forgery attacks, but there appears to be no specific mechanism to restrict which methods can be called on a component from the frontend.

### Missing Mitigations
1. There is no method whitelist/allowlist feature to explicitly declare which methods are allowed to be called from the frontend.
2. No automatic protection against calling private/protected methods (those starting with `_`).
3. No decorator or annotation system to mark methods as "public" for frontend invocation.

### Preconditions
- The attacker needs access to the frontend application.
- The attacker needs to know or discover component names and method names.
- The application must include a component with sensitive methods that perform privileged operations.

### Source Code Analysis
In `call_method_parser.py`, the function `parse_call_method_name` extracts method names and arguments from request payloads:

```python
def parse_call_method_name(call_method_name: str):
    """
    Parses the method name from the request payload into a set of parameters to pass to
    a method.
    """
    is_special_method = False
    args: List[Any] = []
    kwargs: Dict[str, Any] = {}
    method_name = call_method_name

    # Deal with special methods that start with a "$"
    if method_name.startswith("$"):
        is_special_method = True
        method_name = method_name[1:]

    tree = ast.parse(method_name, "eval")
    statement = tree.body[0].value

    if tree.body and isinstance(statement, ast.Call):
        call = tree.body[0].value
        method_name = call.func.id
        args = [eval_value(arg) for arg in call.args]
        kwargs = {kw.arg: eval_value(kw.value) for kw in call.keywords}

    # Add "$" back to special functions
    if is_special_method:
        method_name = f"${method_name}"

    return method_name, tuple(args), MappingProxyType(kwargs)
```

While this parsing is relatively safe (using AST rather than direct `eval()`), it does not contain any validation of which methods can be called.

In `views/action_parsers/call_method.py`, the framework attempts to call methods with appropriate type conversion of arguments:

```python
def _call_method_name(component: UnicornView, method_name: str, args: Tuple[Any], kwargs: Dict[str, Any]) -> Any:
    """
    Calls the method name with parameters.

    Args:
        param component: Component to call method on.
        param method_name: Method name to call.
        param args: Tuple of arguments for the method.
        param kwargs: Dictionary of kwargs for the method.
    """

    if method_name is not None and hasattr(component, method_name):
        func = getattr(component, method_name)

        parsed_args: List[Any] = []
        parsed_kwargs = {}
        arguments = get_method_arguments(func)
        type_hints = get_type_hints(func)

        for argument in arguments:
            if argument in type_hints:
                type_hint = type_hints[argument]

                # Check that the type hint is a regular class or Union
                # (which will also include Optional)
                # TODO: Use types.UnionType to handle `|` for newer unions
                if not isinstance(type_hint, type) and get_origin(type_hint) is not Union:
                    continue

                is_model = False

                try:
                    is_model = issubclass(type_hint, Model)
                except TypeError:
                    pass

                if is_model:
                    DbModel = type_hint  # noqa: N806
                    key = "pk"
                    value = None

                    if not kwargs:
                        value = args[len(parsed_args)]
                        parsed_args.append(DbModel.objects.get(**{key: value}))
                    else:
                        value = kwargs.get("pk")
                        parsed_kwargs[argument] = DbModel.objects.get(**{key: value})
```

This code is particularly concerning as it will automatically fetch Django model instances from the database when a method parameter has a Model type hint. An attacker could provide any primary key and fetch any record from the database, regardless of whether they should have access to it.

### Security Test Case
1. Identify an application built with Django-Unicorn that has a component with a sensitive method, for example:

```python
class AdminComponent(UnicornView):
    def delete_user(self, user_id):
        # Delete a user from the database
        User.objects.get(id=user_id).delete()

    def view_user_data(self, user: User):
        # Return sensitive user data
        return user.get_sensitive_data()
```

2. Craft a JavaScript attack to call these methods:

```javascript
// Call method with primitive argument
Unicorn.call('admin-component', 'delete_user', 123);

// Call method with Model type parameter - will fetch User with ID 456 from database
Unicorn.call('admin-component', 'view_user_data', 456);
```

3. Verify that the method executes without any authorization check, potentially:
   - Deleting a user that the current user shouldn't be able to delete
   - Accessing sensitive data for a user that the current user shouldn't be able to view

4. For methods not exposed through UI elements (hidden methods), discover them through source code inspection or trial and error with common method names.

## Model Exposure Through Model Type Hints (High)

### Description
Django-Unicorn automatically attempts to fetch model instances from the database when a component method has a parameter with a Django Model type hint. When calling a method from the frontend, if the method's parameter is typed as a Django Model, the framework will automatically retrieve that model from the database using the provided primary key. This could allow an attacker to access model instances they shouldn't have access to, as there's no validation that the current user has permission to view or manipulate that model instance.

### Impact
An attacker could potentially access any model instance in the database by calling a method with the appropriate type hint and providing the primary key. This could lead to unauthorized access to sensitive data, including data belonging to other users, which is a serious privacy and security breach.

### Currently Implemented Mitigations
There are no automatic mitigations for this issue. The framework relies on developers to implement their own access control checks within each method, but doesn't provide any built-in protection against unauthorized model access.

### Missing Mitigations
1. No automatic permission checking when retrieving model instances based on type hints.
2. No way to specify which models are allowed to be accessed from the frontend.
3. No input validation for model primary keys provided from the frontend.

### Preconditions
- The attacker needs access to the frontend application.
- The application includes a component with methods that have Django Model type hints.
- The attacker needs to know or guess valid primary keys for the target models.

### Source Code Analysis
In `django_unicorn/views/action_parsers/call_method.py`, the method `_call_method_name` handles calling component methods. When a parameter has a Model type hint, it automatically fetches the model from the database:

```python
if is_model:
    DbModel = type_hint  # noqa: N806
    key = "pk"
    value = None

    if not kwargs:
        value = args[len(parsed_args)]
        parsed_args.append(DbModel.objects.get(**{key: value}))
    else:
        value = kwargs.get("pk")
        parsed_kwargs[argument] = DbModel.objects.get(**{key: value})
```

This code automatically fetches any model instance based solely on its primary key, without any permission checks. The model is fetched using `DbModel.objects.get(**{key: value})`, which means it will retrieve the model even if the user shouldn't have access to it.

The framework doesn't provide any built-in way to restrict which models can be accessed or to perform permission checks before retrieving a model.

### Security Test Case
1. Identify a Django-Unicorn component with a method that accepts a Django model parameter:

```python
class UserProfileComponent(UnicornView):
    def show_profile(self, user: User):
        # Display user profile
        self.profile_data = {
            'username': user.username,
            'email': user.email,
            'private_data': user.private_data
        }
```

2. Craft a JavaScript call to access a model instance the current user shouldn't have access to:

```javascript
// Assuming the current user is a regular user, attempt to access an admin user's data
const adminUserId = 1;  // Usually admin users have low IDs
Unicorn.call('user-profile-component', 'show_profile', adminUserId);
```

3. Verify that the method executes and exposes data from the admin user that the current user shouldn't have access to.

4. Try to access sensitive models by enumerating different model type hints:

```javascript
// Try different user IDs to access other user accounts
for (let i = 1; i <= 10; i++) {
    Unicorn.call('user-profile-component', 'show_profile', i);
}
```

5. Examine the component's state or response to confirm unauthorized access to the model data.
