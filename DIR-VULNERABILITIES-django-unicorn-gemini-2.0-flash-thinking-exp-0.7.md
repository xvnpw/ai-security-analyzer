### Vulnerability List

*   #### Vulnerability Name: Unsafe Deserialization via Pickle in Component Caching
    *   **Description:**
        1.  The `django-unicorn` library utilizes Django's caching mechanism to store component state for performance optimization when `SERIAL['ENABLED']` is set to `True`.
        2.  The library employs Python's `pickle` library to serialize component objects before storing them in the cache and deserialize them upon retrieval.
        3.  Deserializing data from untrusted sources using `pickle` is inherently unsafe. An attacker who can control or inject malicious data into the Django cache can leverage this to execute arbitrary code on the server when the cached component is deserialized.
        4.  Specifically, the functions `cache_full_tree` and `restore_from_cache` in `django_unicorn\cacher.py` are responsible for serialization and deserialization using `pickle`.
    *   **Impact:**
        *   Critical. Successful exploitation of this vulnerability allows for Remote Code Execution (RCE).
        *   An attacker can gain full control over the server by executing arbitrary code, potentially leading to data breaches, system compromise, and denial of service.
    *   **Vulnerability Rank:** Critical
    *   **Currently Implemented Mitigations:**
        *   None. The provided code implements component caching using `pickle` without any apparent mitigations against deserialization vulnerabilities.
    *   **Missing Mitigations:**
        *   Replace `pickle` with a secure serialization format like JSON or other safer alternatives that are not susceptible to code execution during deserialization.
        *   Implement cryptographic signing or encryption of cached data to ensure data integrity and authenticity. This would prevent tampering with cached data and ensure that only trusted data is deserialized.
    *   **Preconditions:**
        *   Component caching must be enabled in `django-unicorn` settings by setting `UNICORN['SERIAL']['ENABLED'] = True` in `settings.py`.
        *   An attacker needs to find a way to inject malicious pickled data into the Django cache. This might be achieved through various means depending on the cache backend and application vulnerabilities, such as cache poisoning or exploiting other vulnerabilities that allow cache manipulation.
    *   **Source Code Analysis:**
        1.  **File:** `django_unicorn\cacher.py`
        2.  **Function:** `cache_full_tree(component)`
            ```python
            def cache_full_tree(component: "django_unicorn.views.UnicornView"):
                # ...
                with CacheableComponent(root) as caching:
                    for _component in caching.components():
                        cache.set(_component.component_cache_key, _component)
            ```
            *   This function serializes the component tree. Inside `CacheableComponent`, the `pickle.dumps` is called implicitly when the component is stored in cache via `cache.set(_component.component_cache_key, _component)`.
        3.  **File:** `django_unicorn\cacher.py`
        4.  **Function:** `restore_from_cache(component_cache_key: str, request: Optional[HttpRequest] = None)`
            ```python
            def restore_from_cache(
                    component_cache_key: str,
                    request: Optional[HttpRequest] = None
                ) -> "django_unicorn.views.UnicornView":
                # ...
                cached_component = cache.get(component_cache_key)

                if cached_component:
                    # ...
                    root: django_unicorn.views.UnicornView = cached_component
                    # ...
            ```
            *   This function retrieves and deserializes the component from the cache using `cache.get(component_cache_key)`. The vulnerability lies in the implicit `pickle.loads` operation performed by Django's cache backend when retrieving data that was serialized with `pickle`.
        5.  **File:** `django_unicorn\components\unicorn_view.py`
        6.  **Method:** `_cache_component` and `create`
            *   These methods in `UnicornView` class call `cache_full_tree` and `restore_from_cache` respectively, orchestrating the caching and retrieval process.
        7.  **Vulnerable Code Flow Visualization:**

            ```mermaid
            sequenceDiagram
                participant User
                participant Application
                participant Cache
                Application->>Cache: cache.set(component_cache_key, pickled_component)  (django_unicorn\cacher.py - cache_full_tree) - Serialization with pickle.dumps
                Note right of Cache: Component state is serialized and stored in cache
                User->>Application: Request for component
                Application->>Cache: cached_component = cache.get(component_cache_key)  (django_unicorn\cacher.py - restore_from_cache) - Deserialization with pickle.loads (implicit by Django cache backend)
                Note right of Cache: Potentially malicious pickled data is retrieved
                Cache-->>Application: cached_component
                Application->>Application: Component state is restored from deserialized data
                Application-->>User: Response with rendered component
            ```

    *   **Security Test Case:**
        1.  **Setup:**
            *   Create a new Django project.
            *   Install `django-unicorn`.
            *   Add `django_unicorn` to `INSTALLED_APPS`.
            *   Configure `django_unicorn` in `settings.py` to enable caching:
                ```python
                UNICORN = {
                    "SERIAL": {"ENABLED": True},
                }
                ```
            *   Ensure a cache backend (other than `dummy`) is configured in `CACHES` in `settings.py` (e.g., `LocMemCache` for testing).
            *   Include `django_unicorn.urls` in `urls.py`.
            *   Create a simple Unicorn component (e.g., `test_component` in app `test_app`) with a basic state variable.
        2.  **Initial Render and Cache Population:**
            *   Create a Django template that includes the `test_component` using `{% unicorn 'test_component' %}`.
            *   Access the template in a browser to render the component and populate the cache with a serialized component state.
        3.  **Craft Malicious Pickle Payload:**
            *   Use Python's `pickle` library to create a malicious payload. For example, to execute `os.system('touch /tmp/pwned')` upon deserialization:
                ```python
                import pickle
                import os
                class EvilPayload(object):
                    def __reduce__(self):
                        return (os.system, ('touch /tmp/pwned',))

                payload = pickle.dumps(EvilPayload())
                # Save the payload to a file or variable for easy access
                with open('malicious_payload.pickle', 'wb') as f:
                    f.write(payload)
                ```
        4.  **Replace Cached Data with Malicious Payload:**
            *   Identify the cache key for the `test_component`. This is usually in the format `unicorn:component:{component_id}`. You can find the component ID in the rendered HTML source code (look for `unicorn:id` attribute on the root element of the component).
            *   Use Django's cache API to manually replace the cached data associated with the component's key with the malicious pickle payload. For `LocMemCache`, you can access the cache directly:
                ```python
                from django.core.cache import caches
                cache = caches['default'] # or your configured cache alias
                component_id = 'your_component_id' # Replace with the actual component ID
                cache_key = f'unicorn:component:{component_id}'

                with open('malicious_payload.pickle', 'rb') as f:
                    malicious_data = f.read()

                cache.set(cache_key, malicious_data)
                print(f"Malicious payload set in cache for key: {cache_key}")
                ```
        5.  **Trigger Component Retrieval and Deserialization:**
            *   Refresh the page in the browser where the `test_component` is rendered. This action triggers `django-unicorn` to retrieve the component from the cache.
        6.  **Verify Code Execution:**
            *   Check if the command in the malicious payload was executed on the server. In this example, verify if the file `/tmp/pwned` was created on the server. If the file exists, it confirms successful Remote Code Execution via unsafe deserialization.
