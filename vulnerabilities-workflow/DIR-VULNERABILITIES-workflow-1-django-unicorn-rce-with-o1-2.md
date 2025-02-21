- **Vulnerability Name**: Insecure Deserialization Leading to Remote Code Execution
  - **Description**:
    1. The application uses Python’s `pickle` to store and retrieve full component objects in the Django cache (`cache_full_tree` and `restore_from_cache`).
    2. A component receives a short 8-character string (from `shortuuid.uuid()[:8]`) as its unique ID.
    3. An attacker can guess or brute-force this component ID due to the limited space of an 8-character short UUID.
    4. By injecting a malicious `pickle` payload at the key `unicorn:component:<guessed-id>` in the Django cache (for instance, in a misconfigured or publicly accessible Redis/Memcache server), the attacker can coerce the application to call `pickle.loads` on untrusted data during `restore_from_cache`.
    5. This untrusted deserialization allows the attacker to execute arbitrary Python code once the legitimate user triggers that same component ID.
  - **Impact**:
    - Complete Remote Code Execution (RCE). An attacker can run arbitrary commands or Python code with the permissions of the Django application process.
  - **Vulnerability Rank**: critical
  - **Currently Implemented Mitigations**:
    - None. Though the code tries to cache only valid component objects, there is no signature check or secure alternative to `pickle.loads`.
  - **Missing Mitigations**:
    1. Use a cryptographically strong, non-conflicting component ID or require secure random tokens that cannot be easily guessed.
    2. Store a secure HMAC or signature in the cache to verify data integrity before unpickling.
    3. Replace `pickle` with a safe serialization method (e.g., JSON without objects, or a specialized safe library).
    4. Restrict or authenticate access to the cache so that untrusted users cannot write arbitrary data to these keys.
  - **Preconditions**:
    - Attacker can brute-force or guess the short 8-character component ID.
    - Attacker can place a malicious payload in the Django cache at the corresponding `unicorn:component:<component-id>` key.
  - **Source Code Analysis**:
    1. `django_unicorn\cacher.py` defines `cache_full_tree()` and `restore_from_cache()`.
    2. `restore_from_cache()` calls `pickle.loads(cached_data)` directly. No verification or cryptographic check is done.
    3. `component_id` is generated in `unicorn\templatetags\unicorn.py` or in `UnicornView.as_view`, where `shortuuid.uuid()[:8]` is used, creating a small keyspace.
    4. The combination of short ID + unguarded unpickling can lead to RCE.
  - **Security Test Case**:
    1. Deploy a Redis/Memcache server that is accessible to the attacker or intercept the application’s cache store.
    2. Pick an 8-character random string that is likely to appear as a component ID (e.g., “abcxyz12”).
    3. Generate a malicious pickle payload locally (e.g., using `pickle` plus a custom `__reduce__` method).
    4. Insert that serialized pickle under the key `unicorn:component:abcxyz12` (or whichever ID the attacker wants to target) into the cache.
    5. In a browser or script, load the page that references the same component ID (for example, by forcing or reusing a guessed link, or by forging the component’s ID in a request).
    6. Observe that the Django process unpickles the attacker’s data, allowing arbitrary code execution.

---

- **Vulnerability Name**: Class Pollution via Unrestricted Property Setting
  - **Description**:
    1. The component’s code allows external user input to update Python object attributes through methods like `_set_property()`.
    2. The logic in `_set_property()` calls `setattr(self, name, value)` directly without verifying that the attribute is truly safe to set.
    3. A malicious user can craft calls that set special or internal attributes (e.g. `__class__`, `parent`, `_someprivate`, or similar) because no strict check is enforced.
    4. This can lead to “class pollution,” letting an attacker manipulate the Python object’s structure or force the component into unexpected states.
    5. In extreme scenarios, it can escalate to code execution if the attacker manages to reassign critical class-level references or break out of normal attribute usage.
  - **Impact**:
    - High severity. Attackers may overwrite internal references, bypass certain validations, or disrupt logic by rewriting component fields. While it may require additional environment details to push it to code execution, the foundation for hijacking the Python class is present.
  - **Vulnerability Rank**: high
  - **Currently Implemented Mitigations**:
    - The code has `_is_public(name)` checks, but those primarily prevent display of attributes in the template context, not setting them from user-supplied data.
    - No direct block exists in `_set_property` to reject private or magic attribute names.
  - **Missing Mitigations**:
    1. Enforce an allowlist for which properties can be updated (only recognized public fields).
    2. Reject or ignore property names starting with `_` or containing `__` to prevent Python internals from being overwritten.
    3. Validate that the attribute matches known fields so that no unapproved mutation can occur.
  - **Preconditions**:
    - Attacker can author or tamper with requests that set or update component field names, either via crafted JavaScript calls or template parameters.
    - The application exposes these components publicly with no attribute-level checks.
  - **Source Code Analysis**:
    1. `unicorn_view.py`, especially the `_set_property()` method, sets arbitrary attributes:
       ```python
       setattr(self, name, value)
       ```
    2. `_is_public()` only excludes private attributes from being *serialized*, but does not prevent a malicious user from naming or updating them.
    3. This can be exploited to manipulate internal fields, e.g., `__class__` or reference to `parent`, possibly chaining with other logic for deeper compromise.
  - **Security Test Case**:
    1. Set up or intercept a request that updates a field in the component (e.g., JSON or form data which is ultimately used by `_set_property`).
    2. Inject an attribute name like `__class__` or `_secret_field` or `parent.force_render`.
    3. Confirm that the server’s `_set_property()` method processes and stores the new attribute or overwrites a critical internal attribute with no error.
    4. Observe unexpected changes in the object’s behavior (e.g., hooking new references, toggling internal flags, or corrupting the parent relationship).
