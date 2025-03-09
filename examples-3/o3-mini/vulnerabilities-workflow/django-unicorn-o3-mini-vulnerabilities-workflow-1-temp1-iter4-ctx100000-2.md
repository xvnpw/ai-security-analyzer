# Vulnerabilities List

## Insecure Deserialization via Pickle in Component Caching

- **Description:**
  The framework caches the serialized state of its component objects by pickling them. In the caching code (for example, within the helper class that uses Python’s `pickle.dumps()` and later calls `pickle.loads()` to restore component state), the use of pickle makes the cached state inherently unsafe. An external attacker who can write to—or inject data into—the cache backend (for example, if a shared Redis or Memcached instance is misconfigured or publicly accessible) could replace a valid serialized component state with a crafted malicious payload. When the framework later deserializes this payload, arbitrary Python objects (and commands) may be constructed and executed.

  **Step‑by‑step how an attacker could trigger it:**
  1. An attacker determines or guesses that the deployed application is using the Django cache backend (via a key name such as “unicorn:component:{component_id}”).
  2. The attacker finds that the cache backend is accessible (for example, because of misconfiguration of Redis/Memcached or use of a shared caching backend).
  3. Using low‑level access to the cache system, the attacker writes a malicious payload—crafted with Python’s pickle—to the cache key corresponding to a target component.
  4. When an end user’s component is refreshed (via an AJAX call or periodic polling), the framework calls `pickle.loads()` on the cached data, deserializing the attacker’s payload and executing arbitrary code.

- **Impact:**
  Successful exploitation of this vulnerability would allow an attacker to run arbitrary Python code on the server. This could lead to full remote code execution, compromise of application data, complete server takeover, defacement of content, or lateral movement into other parts of the deployment.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
  - The framework restricts the use of pickle to internal component state caching only (i.e. components are serialized and deserialized automatically by the cache helpers).
  - Most deployments use local or secured caching backends (for example, Django’s local memory cache or a properly secured Redis/Memcached instance) so that untrusted parties do not have write access to the cache.
  - The caching key format (typically “unicorn:component:{component_id}”) is deterministic and not based on user input.

- **Missing Mitigations:**
  - There is no built‑in signing or integrity verification of the pickled data so that the framework can detect tampering.
  - No fallback exists to use a safer serialization mechanism (such as JSON) for caching component state.
  - The framework does not verify that the deserialized data is of an expected type prior to restoring component state.
  - The framework leaves complete responsibility for securing the caching backend to the deployment configuration.

- **Preconditions:**
  - The application’s cache backend must be writable (or injectable) by an attacker. This can occur if systems such as Redis or Memcached are inadvertently exposed on untrusted networks or misconfigured with open access.
  - The application must be using the default pickle‑based caching logic for component state rather than an overridden, safer implementation.

- **Source Code Analysis:**
  - In the caching helper module (for example, in `django_unicorn/cacher.py`), the component state is serialized via `pickle.dumps()` before being stored in the cache.
  - The corresponding cache restoration function (often named similarly to `restore_from_cache()`) retrieves the cached bytes and immediately calls `pickle.loads()` on the result without any further validation or signature check.
  - Because the standard Python pickle module is inherently unsafe when loading data from an untrusted source, the lack of additional integrity or type‑checks opens the door for an attacker who can manipulate the cache contents.

- **Security Test Case:**
  *Test Objective:* Verify that if an attacker injects a malicious pickle payload into the cache backend, the framework will deserialize and execute that payload.

  **Step‑by‑step testing procedure:**
  1. **Setup a Test Cache Environment:**
     - Configure the Django settings to use a cache backend that can be accessed and written to by test code (or use a simulated/controlled Redis instance).
  2. **Craft a Malicious Pickle Payload:**
     - Create a dummy Python class (or use an existing harmless test “payload” function) whose unpickling produces a visible side‑effect (such as writing to a log or modifying a global state).
     - Use `pickle.dumps(payload_instance)` to create a pickled payload representing the malicious object.
  3. **Inject the Malicious Payload:**
     - Identify a component ID and compute the corresponding cache key (for example, “unicorn:component:<malicious_component_id>”).
     - Write the malicious pickle payload directly into the cache using Django’s cache API.
  4. **Trigger Component Restoration:**
     - Simulate an AJAX (or other) request that causes the framework to restore the component state from the cache by calling the restoration function.
  5. **Validation:**
     - Verify that the payload’s side effect occurs (or that an insecure operation is performed). In a controlled test, the expected behavior might be an exception or a logged output indicating that the payload was executed.
  6. **Tear Down:**
     - Clear the cache to ensure subsequent tests are not affected.
