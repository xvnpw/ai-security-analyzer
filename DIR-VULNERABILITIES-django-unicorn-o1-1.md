## 1. Insecure Deserialization via Pickle in `CacheableComponent`

**Description**
The application caches entire component objects using Python’s `pickle` (`cache.set(_component.component_cache_key, _component)` in [`django_unicorn/cacher.py`](../django-unicorn/django_unicorn/cacher.py)). When the component is subsequently retrieved from the cache and unpickled, arbitrary code execution can occur if the cached data has been tampered with or injected by an attacker. Because each component is identified by only an 8-character short UUID (`shortuuid.uuid()[:8]`), attackers could potentially guess or brute-force a valid `component_id`. If the cache service is network-accessible or not adequately protected, this makes it possible for an external attacker to place malicious pickle data under a guessed `component_id` and achieve Remote Code Execution (RCE) upon deserialization.

Step by step how an attacker could trigger it:
1. An attacker enumerates or brute-forces 8-character UUIDs (for example, using a standard character set).
2. The attacker injects a maliciously crafted pickle under a cache key matching a guessed `component_id` (e.g., `unicorn:component:1234abcd`).
3. The application calls `restore_from_cache(component_cache_key)` which does `cache.get(...)`, then unpickles the data using `pickle.loads`.
4. Unpickling the crafted payload executes arbitrary code embedded by the attacker.

**Impact**
Successful exploitation leads to arbitrary code execution with full privileges of the Django process, effectively compromising the entire server.

**Vulnerability Rank**
**Critical**

**Currently Implemented Mitigations**
- The code checks for pickling errors (`pickle.PicklingError`, `NotImplementedError`, etc.) before caching, which only prevents storing unpicklable objects, not malicious objects.
- `shortuuid` is used to generate `component_id`, but it is truncated to 8 characters and does not adequately mitigate the possibility of guessing or brute forcing.

**Missing Mitigations**
- No integrity check (e.g., signing cached data) before unpickling.
- No encryption or strongly protected keys to ensure the cache data has not been manipulated.
- Reliance on short IDs (8 characters) which are guessable over time.
- No mechanism to verify the authenticity of the unpickled data (e.g., HMAC or digital signature).

**Preconditions**
- An attacker can either write to the application’s cache (e.g., via network access to a misconfigured cache server) or guess the cache key and supply malicious data.
- The code calls `pickle.loads` on the attacker-supplied data upon restoring from cache.

**Source Code Analysis**
- In [`django_unicorn/cacher.py`](../django-unicorn/django_unicorn/cacher.py) under `cache_full_tree(component)`, the code:
  ```python
  with CacheableComponent(root) as caching:
      ...
      cache.set(_component.component_cache_key, _component)
  ```
  stores pickled objects in the cache.
- Later, in `restore_from_cache`:
  ```python
  cached_component = cache.get(component_cache_key)
  # unpickling happens implicitly by retrieving from the cache
  ```
  The component is rehydrated without verifying the cache content integrity.

**Security Test Case**
1. Locate or guess a valid `component_id`, for instance `abcd1234`.
2. On a local test environment, configure the Django cache to be accessible.
3. Use a Python script that stores a malicious pickle under the key `unicorn:component:abcd1234` in the cache (for example, via direct memcached or Redis calls).
4. Make an HTTP request that causes the application to load `component_id="abcd1234"`.
5. Observe arbitrary code execution on the server once `pickle.loads` is called while restoring the malicious payload from the cache.


## 2. Potential Cross-Site Scripting (XSS) via `Meta.safe` Fields

**Description**
If a component class sets certain fields in `Meta.safe`, the framework calls Django’s `mark_safe` on corresponding values (see the `render` logic in [`django_unicorn/views/__init__.py`](../django-unicorn/django_unicorn/views/__init__.py), around line 218). Any user input that is stored in these “safe” fields is rendered unescaped in the browser, allowing an external attacker to inject arbitrary HTML/JavaScript. For instance, if a component’s `Meta` class has `safe = ["description"]`, and an attacker can supply `<script>alert(1)</script>` to `description`, it will be passed through as-is to the client.

Step by step how an attacker could trigger it:
1. A component sets `safe = ["description"]` in its `Meta` class.
2. The user (attacker) supplies malicious markup such as `<script>alert(1)</script>` in the `description` property.
3. When the component re-renders, the code calls `mark_safe` on `description`, disabling Django’s escaping.
4. The script runs in the victim’s browser, leading to XSS.

**Impact**
Enabling an attacker to run arbitrary JavaScript in a visitor’s browser can lead to session hijacking, credential theft, or direct manipulation of the application interface for fraudulent actions.

**Vulnerability Rank**
**High**

**Currently Implemented Mitigations**
- By default, Django auto-escapes unless `mark_safe` is invoked. This library only calls `mark_safe` when a developer explicitly places a field in `Meta.safe`.

**Missing Mitigations**
- No server-side HTML sanitization or content filtering for fields marked as safe.
- No warnings in the code that user-supplied content in these fields is rendered unescaped.

**Preconditions**
- The target component’s `Meta` class lists a field in `safe`.
- The attacker can submit or control the data for that field.

**Source Code Analysis**
- In [`django_unicorn/views/__init__.py`](../django-unicorn/django_unicorn/views/__init__.py), the relevant lines:
  ```python
  # Mark safe attributes as such before rendering
  for field_name in safe_fields:
      value = getattr(component, field_name)
      if isinstance(value, str):
          setattr(component, field_name, mark_safe(value))
  ```
  This manually bypasses Django’s escaping for any string field named in `Meta.safe`.

**Security Test Case**
1. Create a component with `class Meta: safe = ["description"]`.
2. Submit `description="<script>alert('XSS');</script>"` through any form or direct manipulation of the model.
3. Trigger the component update so that `description` is re-rendered.
4. Observe that the script is included and executed in the page, confirming XSS.

----

*These vulnerabilities represent serious security concerns for any production deployment, especially if the cache is accessible or if user input is passed into “safe” fields. Address them promptly by removing pickle from untrusted caching, introducing signature checks or alternative serialization methods, and avoiding `mark_safe` for user-submitted content.*
