## 1. Vulnerability Name: Insecure Deserialization via Django Cache (Pickle‑based Component Caching)

**Description:**
The framework caches full component states by serializing them via Python’s built‑in pickle. In the class `CacheableComponent` (located in `django_unicorn/cacher.py`), views are “pickled” using `pickle.dumps` and are later restored with an unverified call to `pickle.loads` (for example, in the `__exit__` method and helper function `restore_from_cache`). An attacker who can write to or manipulate a cache backend (for example, a misconfigured Redis or Memcached instance) may inject a malicious pickle‑serialized payload. When the application later loads the cached state, attacker‑supplied code is executed.

**Impact:**
This could result in complete remote code execution (RCE) on the host server. An attacker might execute arbitrary Python code, thereby compromising the application and its underlying infrastructure.

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**
– The project relies on Django’s native cache backend (with keys generated internally) to provide isolation for cached pickled objects.

**Missing Mitigations:**
– Use a safer serialization format (for example, JSON or a secure serializer) instead of pickle.
– Perform integrity verification (e.g. via cryptographic signing/HMAC) on the cached payload before unpickling.
– Ensure that the cache backend is securely deployed and access‑controlled.

**Preconditions:**
– The cache backend is either misconfigured (no authentication/isolation) or is shared/multi‑tenant so that an attacker can inject arbitrary payloads.

**Source Code Analysis:**
1. In `django_unicorn/cacher.py`, the component state is pickled and stored using Django’s cache API.
2. Later, when a component is restored (via functions such as `restore_from_cache`), the unprotected call to `pickle.loads` deserializes the potentially tampered data.
3. There is no application‑level mechanism to verify the integrity or origin of the cached payload, leaving it vulnerable when the cache backend is exploitable.

**Security Test Case:**
1. **Setup:** Configure the Django application to use an insecure or misconfigured cache backend (for example, a Redis instance that lacks authentication).
2. **Craft Payload:** Create a malicious pickle payload (for example, one that executes a benign command such as creating a file or logging a marker message).
3. **Injection:** Overwrite or set the cache key used for a component (e.g., using a key format like `"unicorn:component:<component_id>"`) with the malicious payload (via a Redis client or Django shell).
4. **Trigger:** Send an HTTP POST request to the Unicorn AJAX endpoint (such as `/unicorn/message`), ensuring that the request causes a component’s state to be restored.
5. **Observation:** When `pickle.loads` is invoked, verify that the injected payload is executed by checking for expected side effects (e.g., file creation or log message).

---

## 2. Vulnerability Name: Information Disclosure via Detailed Component Load Errors in Dynamic Component Loading

**Description:**
Django Unicorn dynamically loads component classes based on values derived (directly or indirectly) from the URL and request data. When an attacker submits a request that includes a non‑existent or invalid component name (or malformed module path), the system attempts to resolve the module and component class. In the event that the component module or class cannot be found, the error handling routines raise exceptions that include detailed information about the attempted module locations, class naming conventions, and internal file paths. An attacker who triggers these errors can gather knowledge of the framework’s internal structure and naming conventions, potentially aiding further exploits or reconnaissance.

**Step‑by‑step Trigger Scenario:**
1. An attacker crafts an HTTP POST request to the `/message` endpoint with a component name or URL path that does not exist (for example, sending a request to `/message/test-message-module-not-loaded` or `/message/test.dot`).
2. The dynamic loader attempts to resolve the component module and class.
3. Upon failure, the error message (as evidenced in tests such as `test_message_component_module_not_loaded` and `test_message_component_class_not_loaded`) is returned in the response or raised on the server if not caught.
4. If the application is deployed with `DEBUG=True` (or if error handling is not properly hardened in production), detailed information — including internal module paths and attempted locations — is disclosed to the attacker.

**Impact:**
The leakage of internal module names, file paths, and resolving logic can help an attacker map out the application architecture and identify further attack vectors. Although this vulnerability does not directly lead to code execution, it significantly eases reconnaissance efforts and lowers the barrier to launching more advanced attacks.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
– In many test cases (for example, those in `tests/views/message/test_message.py`), exceptions are raised containing detailed error messages. In production, Django’s standard error handling (with `DEBUG=False`) and custom error views are expected to obscure these details.

**Missing Mitigations:**
– The dynamic component loading code lacks sufficient protection against error detail disclosure: detailed error information may be exposed if the application is misconfigured (e.g., with `DEBUG=True` in production).
– Error responses are not consistently sanitized or generalized before being returned to REST clients.

**Preconditions:**
– The application is deployed with unsafe configuration settings (such as `DEBUG=True` or inadequate custom error handling) that do not mask internal error details.
– An attacker controls parts of the URL or request data specifying the component name, allowing them to trigger these error messages.

**Source Code Analysis:**
1. In the view handling messages (typically in `django_unicorn/views/message.py`), the component class is dynamically loaded using the component name provided in the request.
2. If the module or class is not found, errors such as `ComponentModuleLoadError` or `ComponentClassLoadError` are raised.
3. Test cases like `test_message_component_module_not_loaded` and `test_message_component_class_not_loaded` confirm that the exception messages include detailed information such as attempted module locations and file paths.

**Security Test Case:**
1. **Setup:** Deploy the application in an environment where `DEBUG=True` or where error details are not adequately suppressed.
2. **Craft Request:** Using a tool like curl or Postman, send an HTTP POST to the `/message` endpoint with a component name that is known not to exist (e.g., `/message/test-message-module-not-loaded`).
3. **Observe:** Capture the response and verify that the error message includes detailed internal information (such as module names, attempted import paths, or file paths).
4. **Verification:** Confirm that in a correctly configured production environment (with `DEBUG=False` and proper error handling), such detailed error information is not disclosed.
