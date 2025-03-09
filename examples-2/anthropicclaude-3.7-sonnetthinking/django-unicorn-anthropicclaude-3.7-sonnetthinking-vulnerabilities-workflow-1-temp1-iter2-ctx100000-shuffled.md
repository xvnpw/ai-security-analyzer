# Vulnerabilities

## JavaScript Injection via Unsanitized call() Method

### Description
Django-unicorn provides a JavaScript integration feature through the `call()` method that allows Python code to call JavaScript functions with arguments. A critical vulnerability exists when user-controlled input is passed directly to this method without proper sanitization, allowing attackers to execute arbitrary JavaScript code in the victim's browser.

The vulnerability occurs because arguments passed to the `call()` method appear to be included directly in the AJAX response without any sanitization, as seen in the test files. When these arguments contain malicious JavaScript code, they will be executed on the client side.

Step by step exploitation:
1. Identify a component that uses the `call()` method with user-controlled data
2. Submit malicious JavaScript code as input to the component
3. The component processes this input and passes it to the `call()` method
4. The malicious JavaScript gets included in the AJAX response
5. The browser executes the malicious JavaScript in the victim's context

### Impact
**Critical** - This vulnerability allows attackers to execute arbitrary JavaScript code in victims' browsers, which can lead to:
- Session hijacking
- Theft of sensitive data
- Cross-site request forgery
- Modification of page content
- Further attacks using the victim's browser as a platform

### Currently Implemented Mitigations
There don't appear to be any automatic sanitization mechanisms for the arguments passed to the `call()` method. While django-unicorn has implemented XSS protection for component properties by HTML encoding field values by default (as mentioned in the changelog for version 0.36.0), this protection does not extend to arguments passed to the `call()` method.

### Missing Mitigations
1. Automatic sanitization of arguments passed to the `call()` method
2. Content Security Policy enforcement to restrict what JavaScript can be executed
3. Developer guidelines for safe usage of the `call()` method

### Preconditions
- A django-unicorn component that uses the `call()` method with user-controlled data
- No additional sanitization implemented by the developer

### Source Code Analysis
From examining `django_unicorn/components/unicorn_view.py`, we can see the `call()` method implementation:

```python
def call(self, function_name, *args):
    """
    Add a JavaScript method name and arguments to be called after the component is rendered.
    """
    self.calls.append({"fn": function_name, "args": args})
```

This method simply stores the function name and arguments without any sanitization. These calls are later serialized to JSON and included in the response.

Test files like `test_unicorn_render.py` confirm that the calls are included directly in the rendered HTML:

```python
def test_unicorn_render_calls_with_arg(settings):
    # ...
    assert '"calls":[{"fn":"testCall2","args":["hello"]}]' in html
```

The serialization process doesn't include any sanitization for potentially malicious values in the arguments.

### Security Test Case
1. Create a django-unicorn component with the following code:

```python
class VulnerableComponent(UnicornView):
    user_input = ""

    def update_input(self, text):
        self.user_input = text
        self.execute_javascript()

    def execute_javascript(self):
        # Vulnerability: passing user-controlled data to call()
        self.call("processInput", self.user_input)
```

2. Add the associated JavaScript to your page:

```html
<script>
function processInput(input) {
    document.getElementById("output").innerHTML = input;
}
</script>
```

3. Submit the following payload as input:
```
<img src=x onerror=alert(document.cookie)>
```

4. Observe that the alert executes, demonstrating arbitrary JavaScript execution.

This vulnerability is particularly dangerous because it bypasses Django's built-in XSS protections and allows direct execution of arbitrary JavaScript code in the victim's browser.

## Potential for Data Exposure via JavaScript

### Description
Django-unicorn, by default, exposes all public attributes of a component to JavaScript in the client. While this is a design feature and not a direct vulnerability in the framework itself, it presents a significant risk of inadvertent exposure of sensitive data if developers don't correctly use the `javascript_exclude` feature.

Step by step how data exposure occurs:
1. Developer creates a component with public attributes containing sensitive data
2. The developer fails to add these attributes to the `javascript_exclude` tuple
3. When the component is rendered, all public attributes are serialized to JSON
4. This JSON is included in the initial page HTML and accessible via browser dev tools

### Impact
**High** - This issue can lead to exposure of sensitive information such as:
- Internal configuration details
- User personal information
- Database IDs or other information that should remain server-side
- Authentication tokens or other sensitive values

### Currently Implemented Mitigations
The framework provides the `javascript_exclude` feature that allows developers to specify which attributes should not be exposed to JavaScript:

```python
class Meta:
    javascript_exclude = ("sensitive_data", )
```

### Missing Mitigations
- No automatic detection of potentially sensitive data
- No default exclusion of common sensitive field names
- No warnings or documentation emphasizing the risk

### Preconditions
- A django-unicorn component with sensitive data in public attributes
- Developer not using the `javascript_exclude` feature correctly

### Source Code Analysis
From the `get_frontend_context_variables()` method in `unicorn_view.py`, we can see:

```python
frontend_context_variables = {}
attributes = self._attributes()
frontend_context_variables.update(attributes)

# Remove any field in `javascript_exclude` from `frontend_context_variables`
if hasattr(self, "Meta") and hasattr(self.Meta, "javascript_exclude"):
    if isinstance(self.Meta.javascript_exclude, Sequence):
        for field_name in self.Meta.javascript_exclude:
            # Code to exclude attributes...
```

This confirms that by default, all public attributes are included in the frontend context and sent to the client unless explicitly excluded.

### Security Test Case
1. Create a django-unicorn component with sensitive information:

```python
class ExposedDataComponent(UnicornView):
    # Sensitive data that should not be exposed to client
    internal_api_key = "sk_test_123456789abcdef"
    user_details = {"ssn": "123-45-6789", "dob": "1980-01-01"}

    def process_data(self):
        # Some processing using the sensitive data
        pass
```

2. Add the component to a template:
```html
{% load unicorn %}
{% unicorn 'exposed-data' %}
```

3. View the page source or use browser developer tools to inspect the rendered HTML/JavaScript
4. Observe that the sensitive values are visible in the client-side code

This demonstrates how sensitive data can be inadvertently exposed to clients if not properly excluded from JavaScript serialization.

## Remote Code Execution via Public Method Exposure

### Description
Django-Unicorn provides a reactive component framework where component view methods can be called from the frontend. The framework fails to restrict which methods can be called from the frontend, relying only on the `hasattr` check to determine if a method exists on the component. This allows attackers to call any public method on a component, including those that were not intended to be exposed to the frontend.

To trigger this vulnerability, an attacker would craft a malicious AJAX request to the message endpoint with a payload specifying any public method name in the component that could perform sensitive operations. The framework will execute this method if it exists on the component, regardless of whether it was intended to be called remotely.

### Step-by-Step Exploitation
1. Find a publicly accessible Django application using django-unicorn
2. Identify a component name that is available in the application
3. Use browser developer tools to observe how django-unicorn makes AJAX requests
4. Craft a malicious AJAX request to the `/unicorn/message/{component_name}` endpoint with a payload like:
```json
{
  "actionQueue": [
    {
      "type": "callMethod",
      "payload": {
        "name": "potentially_dangerous_method"
      }
    }
  ],
  "data": {},
  "checksum": "VALID_CHECKSUM",
  "id": "component_id",
  "epoch": 1234567890
}
```
5. If the component has methods that perform sensitive operations (file operations, database queries, etc.), these will be executed by the server.

### Impact
This vulnerability could lead to Remote Code Execution if a component has methods that execute code dynamically or run shell commands. It could also lead to unauthorized access to sensitive data, privilege escalation, or other severe security issues depending on what methods are available in the component. The severity is high because it allows an external attacker to execute arbitrary methods on the server.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The framework implements CSRF protection on all component requests, requiring a valid CSRF token for any method invocation. This protects against CSRF attacks but does not prevent direct API manipulation by an attacker.

The framework also requires that the method exists on the component via `hasattr` check, but this is insufficient for security as it doesn't distinguish between methods intended for frontend use versus backend-only methods.

### Missing Mitigations
1. The framework should implement a whitelist mechanism to explicitly mark methods that can be called from the frontend (e.g., with a decorator).
2. Methods starting with underscores (`_`) should be automatically excluded from being callable.
3. A more robust validation of arguments passed to methods should be implemented to prevent injection attacks.

### Preconditions
- The application must be publicly accessible.
- The application must use django-unicorn for component functionality.
- Components must have methods that perform sensitive operations.

### Source Code Analysis
The vulnerability exists in the `django_unicorn/views/action_parsers/call_method.py` file. When an action of type "callMethod" is received, the framework processes it as follows:

```python
def handle(component_request: ComponentRequest, component: UnicornView, payload: Dict):
    call_method_name = payload.get("name", "")
    # ...
    (method_name, args, kwargs) = parse_call_method_name(call_method_name)
    # ...
    component_with_method = parent_component or component
    component_with_method.calling(method_name, args)
    return_data.value = _call_method_name(component_with_method, method_name, args, kwargs)
```

Then in the `_call_method_name` function:

```python
def _call_method_name(component: UnicornView, method_name: str, args: Tuple[Any], kwargs: Dict[str, Any]) -> Any:
    if method_name is not None and hasattr(component, method_name):
        func = getattr(component, method_name)
        # Parse arguments and call the function
        return func(*parsed_args, **parsed_kwargs)
```

The framework merely checks if the method exists on the component with `hasattr(component, method_name)` before calling it. There's no restriction on which methods can be called, allowing attackers to invoke any public method on the component.

The attack works because in `django_unicorn/views/__init__.py`, the `message` view accepts a component name and processes requests:

```python
@timed
@handle_error
@ensure_csrf_cookie
@csrf_protect
@require_POST
def message(request: HttpRequest, component_name: Optional[str] = None) -> JsonResponse:
    if not component_name:
        raise AssertionError("Missing component name in url")

    component_request = ComponentRequest(request, component_name)
    json_result = _handle_component_request(request, component_request)

    return JsonResponse(json_result, json_dumps_params={"separators": (",", ":")})
```

This endpoint is exposed in `django_unicorn/urls.py`:

```python
urlpatterns = (
    re_path(r"message/(?P<component_name>[\w/\.-]+)", views.message, name="message"),
    path("message", views.message, name="message"),
)
```

### Security Test Case
To test this vulnerability:

1. Create a test Django project with django-unicorn installed
2. Create a component with a potentially dangerous method:
```python
# dangerous_component.py
from django_unicorn.components import UnicornView
import os

class DangerousComponentView(UnicornView):
    output = ""

    def get_system_info(self):
        # This method is not intended to be called from frontend but will work
        self.output = os.popen('uname -a').read()
        return self.output
```

3. Create a template that includes this component:
```html
{% load unicorn %}
{% csrf_token %}
{% unicorn 'dangerous-component' %}
```

4. Use curl or another HTTP client to send an AJAX request to the component endpoint:
```bash
curl -X POST "http://localhost:8000/unicorn/message/dangerous-component" \
  -H "Content-Type: application/json" \
  -H "X-CSRFToken: YOUR_CSRF_TOKEN" \
  -H "Cookie: csrftoken=YOUR_CSRF_TOKEN" \
  -d '{
    "actionQueue": [
      {
        "type": "callMethod",
        "payload": {"name": "get_system_info"}
      }
    ],
    "data": {},
    "checksum": "VALID_CHECKSUM",
    "id": "component_id",
    "epoch": 1234567890
  }'
```

5. Observe that the `get_system_info` method is executed, and system information is returned in the response, demonstrating that arbitrary method execution is possible.

## Cross-Site Scripting (XSS) through Improperly Handled User Input

### Description
Django-Unicorn has a vulnerability related to how it handles user input that is marked as "safe". The framework uses the `mark_safe` function on component fields that are explicitly marked as safe in the component's Meta class. If a field that contains user-controlled data is marked as safe, it will be rendered without HTML escaping, leading to potential XSS attacks.

An attacker could inject malicious JavaScript code into a field that is marked as safe, and this code would be executed when the component is rendered.

### Step-by-Step Exploitation
1. Find a publicly accessible Django application using django-unicorn
2. Identify a component that has fields marked as safe in its Meta class
3. Find an input field that updates such a "safe" field
4. Input malicious JavaScript code like `<script>alert('XSS')</script>` or more sophisticated payloads
5. The injected code will be rendered as-is and executed in the browser

### Impact
Successful exploitation allows an attacker to execute arbitrary JavaScript in the context of other users' browsers, potentially leading to session hijacking, credential theft, or other client-side attacks. The severity is high because it allows an external attacker to execute arbitrary JavaScript in victims' browsers.

### Vulnerability Rank
High

### Currently Implemented Mitigations
By default, Django-Unicorn HTML encodes all field values to prevent XSS attacks. The `safe` fields feature requires explicit opt-in through the Meta class:

```python
class Meta:
    safe = ("something_safe", )
```

### Missing Mitigations
1. The framework should provide clear warnings when a field is marked as safe.
2. Additional validation should be performed on fields marked as safe.
3. Documentation should emphasize the risks of marking user-controlled fields as safe.

### Preconditions
- The application must use django-unicorn components.
- At least one component must have a field marked as safe in its Meta class.
- The field must be controllable by user input.

### Source Code Analysis
In `django_unicorn/views/__init__.py`, the framework processes safe fields before rendering:

```python
# Mark safe attributes as such before rendering
for field_name in safe_fields:
    value = getattr(component, field_name)
    if isinstance(value, str):
        setattr(component, field_name, mark_safe(value))  # noqa: S308
```

The `safe_fields` are determined from the component's Meta class:

```python
safe_fields = []
if hasattr(component, "Meta") and hasattr(component.Meta, "safe"):
    if isinstance(component.Meta.safe, Sequence):
        for field_name in component.Meta.safe:
            if field_name in component._attributes().keys():
                safe_fields.append(field_name)
```

This means that any field listed in `Meta.safe` will be rendered without HTML escaping, potentially leading to XSS if the field contains user-controllable content.

The vulnerability exists because the framework doesn't validate or sanitize the content of fields marked as safe. It relies entirely on developers to ensure that these fields don't contain malicious content.

### Security Test Case
To test this vulnerability:

1. Create a test Django project with django-unicorn installed
2. Create a component with a field marked as safe:
```python
# xss_component.py
from django_unicorn.components import UnicornView

class XssComponentView(UnicornView):
    user_input = "<p>Default text</p>"

    class Meta:
        safe = ("user_input",)
```

3. Create a template that includes this component:
```html
{% load unicorn %}
{% csrf_token %}
<div>
    {% unicorn 'xss-component' %}
    <div>
        Enter HTML: <input unicorn:model="user_input" type="text">
        <div>Rendered output: {{ user_input }}</div>
    </div>
</div>
```

4. Run the application and access it in a browser
5. In the input field, enter a malicious payload like:
```
<img src="x" onerror="alert('XSS')">
```
6. Observe that the JavaScript is executed, demonstrating the XSS vulnerability
