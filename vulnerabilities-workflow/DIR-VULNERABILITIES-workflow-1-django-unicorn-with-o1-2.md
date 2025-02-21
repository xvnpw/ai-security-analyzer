---

## 1. Insecure Deserialization via Cached Pickle Data

**Vulnerability name**
Insecure Deserialization via Cached Pickle Data

**Description**
1. When a Unicorn component instance is cached, the framework serializes (pickles) the entire component object—including its state—using `pickle.dumps()`.
2. The serialized object is stored in a shared or distributed cache (e.g., Redis, Memcache), referenced by a cache key derived from the component’s ID.
3. When restoring the cached view, `pickle.loads()` is called to deserialize the pickled component object.
4. Attackers who can write arbitrary data to the same cache location (e.g., by exploiting misconfigurations that allow shared or unauthenticated cache access) can replace the legitimate serialized data with a malicious pickled payload.
5. On deserialization, Python’s `pickle.loads()` will execute the attacker’s payload, leading to remote code execution under the privileges of the Django application process.

**Impact**
Successful exploitation of this insecure deserialization could allow an external attacker with write access to the cache to run arbitrary code in the context of the web application. This typically leads to complete compromise of the server, data exfiltration, or further pivoting within the infrastructure. Due to the severity of allowing arbitrary code execution, this ranks as a critical vulnerability.

**Vulnerability rank**
critical

**Currently implemented mitigations**
- None specific to mitigating pickle’s insecure deserialization. The code is using a standard Python `pickle.loads()` without integrity checks (e.g., cryptographic signing) or gating.

**Missing mitigations**
- Replace `pickle` with a safer serialization library or mechanism (e.g., JSON, manual whitelisting of fields, or specialized cryptographic signing).
- Restricting write access to the cache is essential. Ensure robust authentication and segregation (e.g., separate cache namespaces, credentials) so that untrusted parties cannot inject malicious data.
- Incorporate a signature or HMAC to validate the authenticity of serialized objects before deserialization.

**Preconditions**
- The attacker can manipulate or overwrite the cache entry for a Unicorn component’s `.component_cache_key`.
- The Django app is running in a production environment where the cache mechanism is accessible (e.g., a Redis or Memcached instance).
- No protective hashing or signing prevents malicious tampering of serialized component data.

**Source code analysis**
- The caching mechanism is implemented in `django_unicorn\django_unicorn\cacher.py`.
- `CacheableComponent.__enter__()` calls `pickle.dumps(component)` to serialize.
- `restore_from_cache()` calls `pickle.loads(...)` to deserialize. No cryptographic integrity checks or whitelisting exist.
- If an attacker injects a malicious pickle payload under the same cache key, `pickle.loads()` will execute attacker-supplied code on the server.

Example relevant excerpts (abbreviated):
```python
# django_unicorn/django_unicorn/cacher.py

with CacheableComponent(component) as caching:
    # ...
    pickle.dumps(component)  # Data is serialized

def restore_from_cache(component_cache_key: str, request: Optional[HttpRequest] = None):
    cached_component = cache.get(component_cache_key)
    if cached_component:
        return pickle.loads(cached_component)  # Data is deserialized unsafely
```

**Security test case**
1. Set the Django instance to use a cache (e.g., Redis) accessible to both the web application and an external user (attacker).
2. The web application runs a Unicorn component that is cached using `CacheableComponent`.
3. The attacker crafts a malicious Python pickle payload which, upon `pickle.loads()`, executes code (e.g., `os.system` call).
4. The attacker overwrites the legitimate Redis key (e.g., `unicorn:component:<ID>`) with the malicious payload.
5. Trigger the application to deserialize—from `restore_from_cache()`—and confirm that arbitrary code was executed with the privileges of the Django process.

By performing this test, it is demonstrated that the framework’s use of pickle for caching places the application at risk of remote code execution if cache integrity is compromised.

---
