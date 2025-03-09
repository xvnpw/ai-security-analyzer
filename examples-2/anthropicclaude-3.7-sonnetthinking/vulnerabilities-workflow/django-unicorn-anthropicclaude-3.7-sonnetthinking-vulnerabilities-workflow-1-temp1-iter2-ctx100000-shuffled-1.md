# VULNERABILITIES

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
