### Vulnerability List:

* **Vulnerability Name:** Insecure Deserialization via Cached Component State

* **Description:**
    1. An attacker can manipulate the cached component state if the caching mechanism is compromised or improperly secured.
    2. Django-unicorn serializes component state for caching purposes using `pickle` (implicitly through `django.core.cache`'s default serializer or explicitly if a different cache backend with pickle serialization is configured).
    3. If an attacker can inject malicious serialized data into the cache, upon deserialization, it can lead to arbitrary code execution on the server.
    4. This could be achieved if the cache storage itself is vulnerable (e.g., exposed Redis instance, compromised memcached, or vulnerabilities in the cache backend implementation), or if there's another vulnerability in the application that allows cache manipulation.
    5. When a user interacts with a component that relies on cached state (e.g., after a server restart or cache invalidation), the application might deserialize the malicious payload, leading to code execution.

* **Impact:**
    * **Critical:** Remote Code Execution (RCE). Successful exploitation allows the attacker to execute arbitrary code on the server hosting the Django application, potentially leading to full system compromise, data breaches, and denial of service.

* **Vulnerability Rank:** Critical

* **Currently Implemented Mitigations:**
    * The code uses `django.core.cache` for caching component state, which by default in Django uses `pickle` for serialization.
    * The `CacheableComponent` class in `django_unicorn.cacher.py` explicitly uses `pickle.dumps` and `pickle.loads` implicitly through Django's cache backend.
    * There are no explicit mitigations in the provided code to prevent insecure deserialization of the cached component state. The code focuses on making components cacheable but not on securing the serialization process itself.

* **Missing Mitigations:**
    * **Input Validation and Sanitization:**  There is no validation or sanitization of the cached data before deserialization.
    * **Secure Serialization:**  Switching from `pickle` to a safer serialization format like JSON (with careful handling of custom objects if needed) or using cryptographic signing of the serialized data to ensure integrity and authenticity.
    * **Cache Access Control:** Implementing proper access control to the cache storage to prevent unauthorized modification of cached data.

* **Preconditions:**
    1. Caching must be enabled in `django-unicorn` (which is the default for performance reasons, especially for features like request queuing).
    2. The Django cache backend must be vulnerable to data injection or manipulation (e.g., due to misconfiguration, vulnerabilities in the backend itself, or another vulnerability in the application that allows cache access).
    3. An attacker needs to be able to inject a malicious serialized payload into the cache, targeting a component's cache key.

* **Source Code Analysis:**
    * **`django_unicorn/cacher.py`:**
        ```python
        import pickle
        from django.core.cache import caches
        from django_unicorn.settings import get_cache_alias

        class CacheableComponent:
            # ...
            def __enter__(self):
                # ...
                for component, *_ in self._state.values():
                    try:
                        pickle.dumps(component) # Serialization using pickle
                    except (TypeError, AttributeError, NotImplementedError, pickle.PicklingError) as e:
                        raise UnicornCacheError(...) from e
                # ...

        def restore_from_cache(component_cache_key: str, request: Optional[HttpRequest] = None) -> "django_unicorn.views.UnicornView":
            cache = caches[get_cache_alias()]
            cached_component = cache.get(component_cache_key) # Deserialization using pickle (implicitly by Django cache)
            # ...
            return cached_component
        ```
        * The `CacheableComponent` class uses `pickle.dumps` to serialize component state before caching.
        * The `restore_from_cache` function retrieves data from the Django cache using `cache.get()`, which implicitly uses `pickle.loads` (or the configured cache backend's deserialization method, which often defaults to pickle or can be configured to use it).
        * There are no checks for the integrity or origin of the cached data before deserialization.

    * **Visualization:**

    ```mermaid
    graph LR
        A[User Interaction] --> B(Unicorn Component);
        B --> C{Cache Enabled?};
        C -- Yes --> D[Serialize Component State (pickle.dumps)];
        D --> E[Cache Storage];
        E -- Malicious Payload Injection --> E;
        F[Component Request] --> G{Cache Hit?};
        G -- Yes --> H[Deserialize Component State (pickle.loads)];
        H --> I[Vulnerable Code Execution];
        G -- No --> J[Normal Component Lifecycle];
    ```

* **Security Test Case:**
    1. **Setup:**
        * Configure Django-unicorn to use caching (default settings usually enable it).
        * Create a simple Unicorn component that uses caching (e.g., a component with a counter that persists across requests due to caching).
        * Identify the cache key used for this component (this might require inspecting the caching logic or debugging).
    2. **Craft Malicious Payload:**
        * Create a Python object that, when pickled and then unpickled, executes arbitrary code. A simple example could be using `os.system` or similar dangerous functions within a class `__reduce__` method or similar pickle exploit techniques.
        * Serialize this malicious object using `pickle.dumps()`.
    3. **Inject Payload into Cache:**
        * Manually inject the crafted malicious pickled payload into the cache storage using the identified cache key. This step depends on the specific cache backend used. For `locmem`, it might be harder to directly inject. For Redis or Memcached, you could use their respective command-line tools or client libraries to `SET` the key with the malicious payload.  If using a file-based cache, you might attempt to overwrite the cache file.
    4. **Trigger Deserialization:**
        * Interact with the Django-unicorn component in the application in a way that triggers the retrieval of the cached state. This could be a page reload, navigating to the component, or performing an action that relies on the cached state.
    5. **Verify Code Execution:**
        * Monitor for evidence of code execution on the server. This could be through:
            * Checking server logs for unexpected activity.
            * Observing changes to the file system if the malicious payload attempts to create or modify files.
            * Using an out-of-band technique (like DNS lookup or HTTP request to a controlled server) within the malicious payload to signal successful execution.

    **Expected Result:** Successful code execution on the server when the malicious payload is deserialized from the cache.

---
* **Vulnerability Name:** Insecure Method Calling via `callMethod` Action

* **Description:**
    1. An attacker can trigger the execution of arbitrary methods on a Unicorn Component by crafting a malicious `callMethod` action in the JSON request.
    2. The `callMethod` action is handled in `django_unicorn.views.action_parsers.call_method.handle`.
    3. The `handle` function parses the method name from the `name` payload using `parse_call_method_name`. This parsing, while it handles arguments and kwargs, does not restrict the method names to a safe list or validate them against allowed methods. The tests in `django_unicorn\tests\call_method_parser\` confirm that the parser is designed to handle various argument types and complex method signatures, but it does not include any checks to ensure the method being called is safe or intended to be publicly accessible.
    4. The parsed `method_name` is then used in `_call_method_name` to retrieve a method from the component using `getattr(component_with_method, method_name)`.
    5. If an attacker can control the `method_name` value in the `callMethod` action, they can potentially call any public method of the Unicorn component, including those not intended to be exposed to client-side calls.
    6. This can lead to unintended state changes, data manipulation, or information disclosure, depending on the functionality of the called methods.

* **Impact:**
    * **High:** Unintended Function Execution and Potential Information Disclosure/Data Manipulation. While it might not directly lead to RCE, it can allow attackers to bypass intended application logic, trigger sensitive actions, or access/modify data through exposed methods. The severity depends on the specific methods exposed in components and their potential impact.

* **Vulnerability Rank:** High

* **Currently Implemented Mitigations:**
    * CSRF protection is enabled for the `message` view via `@csrf_protect` decorator in `django_unicorn.views.__init__.py`, which prevents Cross-Site Request Forgery attacks.
    * Only POST requests are accepted for the `message` view via `@require_POST` decorator.
    * Checksum validation is implemented in `ComponentRequest.validate_checksum` to ensure the integrity of the request data, preventing tampering with data values, but not method names.

* **Missing Mitigations:**
    * **Method Name Validation:** Implement a whitelist or validation mechanism to restrict the allowed method names that can be called via `callMethod` action. Only explicitly allowed methods should be callable from the client-side.
    * **Input Sanitization for Method Arguments:** While type casting is performed on method arguments, ensure proper sanitization and validation of arguments to prevent injection attacks if methods process user-provided data.

* **Preconditions:**
    1. The application must use Unicorn Components with publicly accessible methods (methods not starting with `_`).
    2. An attacker must be able to send POST requests to the `/unicorn/message` endpoint (or the configured Unicorn endpoint).
    3. The attacker needs to know or guess the names of public methods available in the target Unicorn component.

* **Source Code Analysis:**
    * **`django_unicorn\views\action_parsers\call_method.py`:**
        ```python
        def handle(component_request: ComponentRequest, component: UnicornView, payload: Dict):
            # ...
            call_method_name = payload.get("name", "")
            # ...
            (method_name, args, kwargs) = parse_call_method_name(call_method_name)
            # ...
            component_with_method = parent_component or component
            component_with_method.calling(method_name, args)
            return_data.value = _call_method_name(component_with_method, method_name, args, kwargs) # Vulnerable line
            component_with_method.called(method_name, args)
            # ...

        @timed
        def _call_method_name(component: UnicornView, method_name: str, args: Tuple[Any], kwargs: Dict[str, Any]) -> Any:
            # ...
            if method_name is not None and hasattr(component, method_name): # Check if method exists
                func = getattr(component, method_name) # Get method using getattr
                # ...
                return func(*parsed_args, **parsed_kwargs) # Call the method
            # ...
        ```
        * The `handle` function retrieves the `method_name` from the `payload` without any validation against a safe list.
        * `_call_method_name` uses `getattr(component, method_name)` to get the method. If `method_name` is controlled by the attacker, they can access any public method of the component.
        * There is a check `hasattr(component, method_name)` to ensure the method exists, but this is not sufficient to prevent insecure method calling as any public method can be called.

    * **Visualization:**

    ```mermaid
    graph LR
        A[Client Request with callMethod Action] --> B(call_method.handle);
        B --> C{Extract method_name from payload};
        C --> D(parse_call_method_name);
        D --> E(getattr(component, method_name));
        E --> F[Execute Arbitrary Component Method];
    ```

* **Security Test Case:**
    1. **Setup:**
        * Create a Unicorn Component with a public method that performs a sensitive action or returns sensitive information (e.g., a method that deletes a record, changes a setting, or returns internal state). For example:

        ```python
        # example/unicorn/components/sensitive_component.py
        from django_unicorn.components import UnicornView

        class SensitiveComponentView(UnicornView):
            sensitive_data = "This is secret!"

            def expose_sensitive_data(self):
                return self.sensitive_data

            def delete_component(self):
                self.sensitive_data = "Component deleted!" # Simulate a sensitive action
                return "Component deleted"
        ```

        * Create a template that uses this component.

        ```html
        <!-- example/templates/www/sensitive_component_test.html -->
        {% load unicorn %}
        <!DOCTYPE html>
        <html>
        <head>
            <title>Sensitive Component Test</title>
            {% unicorn_scripts %}
        </head>
        <body>
            {% unicorn "sensitive-component" %}
        </body>
        </html>
        ```

        2. **Identify Component ID:** Load the page containing the component and inspect the HTML to find the `unicorn:id` of the `sensitive-component`.
        3. **Craft Malicious Request:** Create a POST request to `/unicorn/message` with the following JSON payload, replacing `COMPONENT_ID` with the actual component ID obtained in the previous step and `METHOD_NAME` with the name of the sensitive method (e.g., `expose_sensitive_data` or `delete_component`):

        ```json
        {
            "id": "COMPONENT_ID",
            "name": "sensitive-component",
            "epoch": 1,
            "checksum": "...",  // Placeholder, checksum will be calculated later
            "data": {},
            "actionQueue": [
                {
                    "type": "callMethod",
                    "payload": {
                        "name": "METHOD_NAME"
                    }
                }
            ]
        }
        ```
        4. **Calculate Checksum:** Calculate the checksum for the `data` part of the JSON payload (which is `{}`). Use the `generate_checksum` function from `django_unicorn.utils`. Replace the placeholder checksum in the JSON payload with the calculated checksum.
        5. **Send Request:** Send the crafted POST request to the `/unicorn/message` endpoint.
        6. **Verify Exploitation:**
            * **For `expose_sensitive_data`:** Check the JSON response. It should contain a `return` value with the sensitive data exposed by the `expose_sensitive_data` method.
            * **For `delete_component`:** Reload the page or interact with the component in a way that would reflect the state change caused by `delete_component`. Verify that the component's state has been changed as a result of calling the method.

    **Expected Result:** Successful execution of the arbitrary method on the component, demonstrating the Insecure Method Calling vulnerability. For example, calling `expose_sensitive_data` should return `"This is secret!"` in the JSON response, and calling `delete_component` should change the component's state.
