# VULNERABILITIES

## 1. Information Disclosure through Component Serialization

### Vulnerability Name
Information Disclosure through Component Serialization

### Description
Django Unicorn automatically serializes all public attributes of a component and sends them to the frontend. If developers include sensitive information in these attributes (database credentials, API keys, personal user data), this information will be exposed in the HTML source code and accessible to any user who can view the page.

To trigger this vulnerability:
1. An attacker would view the source code of a page containing a Unicorn component
2. The attacker would look for the `unicorn:data` attribute on the component's root element
3. This attribute contains a JSON representation of all the component's public attributes, potentially including sensitive information

### Impact
This vulnerability could lead to the exposure of sensitive information such as:
- API keys or tokens
- Database credentials
- Personal user information
- Internal business logic or configuration

### Vulnerability Rank
High

### Currently Implemented Mitigations
The framework provides `Meta.javascript_exclude` and `Meta.exclude` to prevent certain attributes from being serialized to the frontend.

### Missing Mitigations
1. The framework could implement a "whitelist" approach instead of a "blacklist" approach, where only explicitly allowed attributes are serialized
2. Automatic detection and warning for potentially sensitive information in component attributes
3. Better developer documentation about the risks of exposing sensitive data

### Preconditions
A Unicorn component must include sensitive data in public attributes without using the exclusion mechanisms.

### Source Code Analysis
In `unicorn_view.py`, all public attributes of a component are serialized:

```python
def get_frontend_context_variables(self) -> str:
    """
    Get publicly available properties and output them in a string-encoded JSON object.
    """
    frontend_context_variables = {}
    attributes = self._attributes()
    frontend_context_variables.update(attributes)
    # ...
```

And in `unicorn_template_response.py`, these attributes are added to the HTML as a `unicorn:data` attribute:

```python
root_element["unicorn:data"] = frontend_context_variables
```

While there are exclusion mechanisms (`javascript_exclude` and `exclude`), they require developers to explicitly list attributes to exclude, which can be error-prone.

### Security Test Case
1. Create a Unicorn component with sensitive information:
   ```python
   class SensitiveComponent(UnicornView):
       api_key = "secret-api-key-12345"
       user_details = {"ssn": "123-45-6789", "dob": "1980-01-01"}
   ```

2. Render this component in a Django template:
   ```html
   {% unicorn 'sensitive-component' %}
   ```

3. View the source code of the rendered page and locate the `unicorn:data` attribute on the component's root element
4. Verify that the sensitive information is present in this attribute
5. This demonstrates that sensitive information in component attributes is exposed to anyone who can view the page source

## 2. Arbitrary Method Execution

### Vulnerability Name
Arbitrary Method Execution

### Description
Django Unicorn automatically exposes all public methods of a component to be called from the frontend. If a component contains methods that perform sensitive operations (like deleting data or changing permissions) and these methods aren't explicitly protected, an attacker could manipulate the frontend JavaScript to call these methods.

To trigger this vulnerability:
1. An attacker would identify a Unicorn component with a sensitive public method
2. The attacker would use the browser's developer tools to manually trigger a call to this method
3. For example, using `Unicorn.call('component-name', 'sensitive_method')`

### Impact
This vulnerability could allow an attacker to:
- Execute unauthorized actions
- Manipulate or delete data
- Bypass intended application flow
- Escalate privileges if the methods affect permissions

### Vulnerability Rank
High

### Currently Implemented Mitigations
The framework has a protection mechanism that prevents calling methods that start with an underscore or are in a predefined list of protected names.

### Missing Mitigations
1. A "whitelist" approach where only explicitly allowed methods can be called from the frontend
2. CSRF protection specifically for method calls
3. Additional authorization checks in the method-calling logic
4. Better developer documentation about the risks of exposing sensitive methods

### Preconditions
A Unicorn component must include public methods that perform sensitive operations without additional authorization checks.

### Source Code Analysis
In `unicorn_view.py`, the `_is_public` method determines if a method should be exposed to the frontend:

```python
def _is_public(self, name: str) -> bool:
    """
    Determines if the name should be sent in the context.
    """
    # Ignore some standard attributes from TemplateView
    protected_names = (
        # ... list of protected names ...
    )
    # ...
    return not (
        name.startswith("_") or name in protected_names or name in self._hook_methods_cache or name in excludes
    )
```

This uses a "blacklist" approach - any method that doesn't start with an underscore and isn't in the `protected_names` list is considered public and can be called from the frontend.

In the JavaScript side (based on the documentation), methods can be called using:
```javascript
Unicorn.call('component-name', 'method_name');
```

### Security Test Case
1. Create a Unicorn component with a sensitive method:
   ```python
   class AdminComponent(UnicornView):
       def delete_all_users(self):
           # Code to delete all users
           pass

       def get_user_list(self):
           # Code to get user list
           return User.objects.all()
   ```

2. Render this component in a Django template:
   ```html
   {% unicorn 'admin-component' %}
   ```

3. Open the browser's developer console and execute:
   ```javascript
   Unicorn.call('admin-component', 'delete_all_users');
   ```

4. Verify that the method is called successfully
5. This demonstrates that an attacker could call sensitive methods from the frontend without proper authorization checks
