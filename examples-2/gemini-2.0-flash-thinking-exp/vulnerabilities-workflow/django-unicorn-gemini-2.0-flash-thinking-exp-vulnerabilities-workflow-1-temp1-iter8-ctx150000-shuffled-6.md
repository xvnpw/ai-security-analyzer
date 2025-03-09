### Vulnerability List

- Vulnerability Name: Insecure Deserialization in Component Caching
- Description:
    1. The django-unicorn framework implements a caching mechanism to improve performance by storing rendered components in the cache.
    2. When a component is cached, its state and attributes, including potentially complex Python objects, are serialized using Python's `pickle` library.
    3. When a component is requested and found in the cache, the framework deserializes the cached data using `pickle.loads` to restore the component's state.
    4. Python's `pickle` library is known to be vulnerable to insecure deserialization. If an attacker can replace the cached component data with a malicious pickled payload, deserializing this data can lead to arbitrary code execution on the server.
    5. An attacker could potentially compromise the cache backend directly or exploit other vulnerabilities to inject malicious data into the cache.
- Impact: Remote Code Execution (RCE). Successful exploitation of this vulnerability allows an attacker to execute arbitrary Python code on the server hosting the django-unicorn application, potentially leading to complete system compromise, data breaches, and other severe security consequences.
- Vulnerability Rank: Critical
- Currently implemented mitigations:
    - None. The project utilizes `pickle` for serialization and deserialization of cached components without any implemented security measures to prevent insecure deserialization.
- Missing mitigations:
    - Replace `pickle` with a secure serialization format: Migrate from `pickle` to a safer serialization library like `json` if only basic data types need to be serialized, or consider using `dill` with extreme caution and thorough security review if complex Python objects serialization is necessary. However, ideally, avoid deserializing code from cache.
    - Implement data integrity checks: Introduce integrity checks for cached data by using cryptographic signing or Message Authentication Codes (MACs). This would ensure that the cached data has not been tampered with. Before deserializing any data from the cache, verify its integrity using the signature or MAC.
    - Explore alternative caching strategies: Investigate alternative caching approaches that minimize or eliminate the need for deserialization of code. For instance, consider caching only non-executable data or using template fragment caching if applicable.
- Preconditions:
    - Component caching must be enabled in the django-unicorn application. This typically involves configuring `UNICORN['CACHE_ALIAS']` in Django settings to use a cache backend other than the `DummyCache`.
    - An attacker needs to have a way to inject malicious pickled data into the configured cache backend. This could be achieved by directly compromising the cache system itself, or potentially through other vulnerabilities in the application that might allow for cache manipulation (though this is less likely to be directly exposed to external attackers without significant other vulnerabilities being present). The primary threat is likely from internal network breaches or compromised infrastructure where access to the cache system becomes possible.
- Source code analysis:
    - File: `django_unicorn\cacher.py`
    - Vulnerable code path:
        ```python
        # django_unicorn\cacher.py

        def cache_full_tree(component: "django_unicorn.views.UnicornView"):
            # ...
            cache = caches[get_cache_alias()]

            with CacheableComponent(root) as caching:
                for _component in caching.components():
                    cache.set(_component.component_cache_key, _component) # pickle.dumps is called implicitly during cache.set

        def restore_from_cache(
                component_cache_key: str,
                request: Optional[HttpRequest] = None
            ) -> "django_unicorn.views.UnicornView":
            # ...
            cache = caches[get_cache_alias()]
            cached_component = cache.get(component_cache_key) # pickle.loads is called implicitly during cache.get

            if cached_component:
                # ... use cached_component ...
        ```
    - The `cache_full_tree` function serializes `UnicornView` components using `pickle` (implicitly through Django's cache `set` method) before storing them in the cache.
    - The `restore_from_cache` function retrieves components from the cache and deserializes them using `pickle` (implicitly through Django's cache `get` method).
    - There are no visible sanitization or integrity checks in place before or after the `pickle.dumps` and `pickle.loads` operations, making the application vulnerable to insecure deserialization if the cache is compromised.
- Security test case:
    1. **Prerequisites:**
        - Ensure a Django project with django-unicorn is set up and configured to use a cache backend other than `django.core.cache.backends.dummy.DummyCache` (e.g., `django.core.cache.backends.locmem.LocMemCache` for testing).
        - Create a simple Unicorn component for testing purposes.
    2. **Create Malicious Payload:**
        - Prepare a malicious Python class that executes arbitrary code upon deserialization. For example, a class that executes `os.system('touch /tmp/pwned')` in its `__reduce__` method (used by pickle for serialization).
        ```python
        import os
        import pickle
        import django_unicorn

        class MaliciousComponent(django_unicorn.components.UnicornView): # inherit from UnicornView to be cacheable
            def __reduce__(self):
                return (os.system, ('touch /tmp/unicorn_pwned',))

        malicious_component = MaliciousComponent(component_name="test", component_id="malicious_component")
        payload = pickle.dumps(malicious_component)
        ```
    3. **Simulate Cache Poisoning:**
        - Manually poison the cache by directly setting the cache entry for a known component key with the malicious payload. For `locmem` cache, you can access `cache._cache` and overwrite the entry. In a real attack, this step would involve exploiting a vulnerability to inject data into the cache.
        ```python
        from django.core.cache import caches

        cache = caches['default'] # replace 'default' with your configured cache alias
        cache.set('unicorn:component:test_component_id', payload) # replace 'test_component_id' with a known component id
        ```
    4. **Trigger Deserialization:**
        - Send a request to the django-unicorn application that would trigger the retrieval and deserialization of the cached component. This could be a request that normally re-renders the component or any action that might cause the component to be loaded from cache. For example, refresh the page containing the component.
    5. **Verify Code Execution:**
        - Check if the malicious code was executed on the server. In the example payload, we attempt to create a file `/tmp/unicorn_pwned`. Verify if this file exists on the server after triggering the deserialization in step 4. If the file exists, it confirms successful code execution due to insecure deserialization.

This test case demonstrates how a malicious payload, when deserialized by django-unicorn's caching mechanism, can lead to arbitrary code execution, confirming the Insecure Deserialization vulnerability.
