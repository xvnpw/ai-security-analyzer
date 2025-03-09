Below is the updated list containing only vulnerabilities that meet the criteria (valid, not already mitigated, with a vulnerability rank of at least high, and not originating from explicit insecure coding practices in project files):

---

- **Vulnerability Name:** Insecure Deserialization via Pickle Caching
  **Description:**
  The framework caches fully instantiated component view instances (and their complete “tree” of child components) by pickling their state and storing the resulting binary blob in the cache backend. If an attacker can poison or overwrite a cache entry—for example, by exploiting a misconfigured (publicly accessible or unprotected) cache backend—they can inject a malicious pickle payload. When the component is later restored from cache via a call to `restore_from_cache()`, the unverified payload is deserialized via `pickle.loads()`, which may trigger arbitrary code execution.
  **Impact:**
  An attacker capable of controlling the cached blob may execute arbitrary code on the server. This can lead to full system compromise, unauthorized data reading, modification or deletion of application state, and lateral movement into the internal network.
  **Vulnerability Rank:**
  Critical
  **Currently Implemented Mitigations:**
  - The cache backend is expected to be secured (for example, by using a private network with properly configured Memcached or Redis).
  - The caching mechanism is opt‑in (controlled by settings such as UNICORN and CACHE_ALIAS), so developers are expected to use secure backends in production.
  **Missing Mitigations:**
  - There is no intrinsic verification (for example, using a message authentication code) on the pickled blob before deserialization.
  - No alternative safe serialization format (such as JSON) is used for the component state.
  **Preconditions:**
  - Component caching is enabled.
  - The deployed cache backend is misconfigured or insufficiently firewalled (allowing external write access).
  **Source Code Analysis:**
  - In the file `django_unicorn/cacher.py`, the class `CacheableComponent` calls `pickle.dumps(component)` on the component (and its children) before storing them.
  - Later, the framework retrieves the cached data and calls `pickle.loads()` without performing any integrity or authenticity checks.
  - Because pickle is inherently unsafe when deserializing untrusted data, an attacker who can inject a crafted pickle blob will trigger the execution of arbitrary code upon restoration.
  **Security Test Case:**
  1. Configure the Django instance to use a cache backend that is known to be insecure (for example, a publicly accessible Redis or memcached instance).
  2. Enable component caching via the UNICORN settings so that the serialized (pickled) component is stored in the cache.
  3. Identify the cache key (typically of the form `"unicorn:component:<component_id>"`) corresponding to a target component.
  4. Using an external tool or script, directly write a malicious, crafted pickle payload (designed with a malicious `__reduce__` method to execute a benign system command for testing) under the same key in the cache.
  5. Trigger the component’s rendering (for example, via an AJAX request to the appropriate endpoint) such that `restore_from_cache()` is executed.
  6. Verify that the injected payload is executed (e.g., by checking for expected log entries or side effects).

---

*Note:* The previously reported "Directory Traversal in Template Rendering" vulnerability was excluded from this list because it originates from an insecure coding pattern explicitly present in the project files, which falls under the exclusion criteria.
