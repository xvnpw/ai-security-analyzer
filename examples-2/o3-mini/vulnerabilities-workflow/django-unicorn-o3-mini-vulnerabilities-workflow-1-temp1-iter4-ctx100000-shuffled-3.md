# Vulnerability List

---

## Vulnerability Name: Insecure Deserialization via Cache‐Based Pickle Serialization

**Description:**
Django Unicorn caches entire component trees between AJAX requests using Django’s cache backend. In doing so, it serializes “resettable” component attributes by invoking Python’s built‑in pickle module (see the use of `pickle.dumps()` in the `CacheableComponent.__enter__` method and subsequent retrieval via the cache in `restore_from_cache`). If the underlying cache backend (for example, a Redis or Memcached instance) is misconfigured or is externally accessible without proper authentication or network isolation, an attacker who is able to write (or poison) the cache with a malicious pickle payload could later force the application to unpickle that payload when it restores a component. Because pickle is inherently unsafe when processing untrusted data, this scenario could lead to remote code execution (RCE) on the server.

**Impact:**
An attacker able to poison the cache may execute arbitrary code, compromise the entire Django application server, access sensitive data, or pivot to other network components.

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**
- The caching functions are built atop Django’s own caching framework. In many development configurations (for example, using `LocMemCache`), the cache is not exposed over the network.
- The project code does not expose caching APIs externally; components are only restored as part of an internal AJAX update cycle.

**Missing Mitigations:**
- No explicit safeguard or alternative (safe) serializer is used instead of pickle.
- There is no integrity verification (for instance, separate signing) of cached objects prior to unpickling.
- No option is provided to disable caching or opt for safer serialization in production deployments using shared or remotely accessible cache backends.

**Preconditions:**
- The cache backend is misconfigured or deployed in an environment where it is accessible from untrusted networks (or has been modified by an attacker).
- The attacker is an external actor who identifies and overwrites keys used by Django Unicorn (e.g., keys prefixed with `unicorn:component:`) with malicious pickle payloads.
- The application instance is publicly accessible, exposing the caching layer to external manipulation.

**Source Code Analysis:**
1. In **`django_unicorn/cacher.py`**, the `CacheableComponent` context manager strips noncacheable state and calls `cache_full_tree()` to store a pickled version of the component.
2. Later, in **`restore_from_cache()`**, the cached data is retrieved without added verification and unpickled automatically by the cache backend.
3. Since Django’s cache backends (e.g., Redis, Memcached) use pickle by default, an attacker who poisons the cache can force arbitrary code execution when the component is restored.

**Security Test Case:**
1. **Setup:** Configure the Django Unicorn application in a test environment with a cache backend that is externally accessible (for example, a misconfigured Redis or Memcached instance without proper network isolation or authentication).
2. **Injection:** Identify a key matching the pattern `unicorn:component:<component_id>` in the cache backend and overwrite its value with a malicious pickle payload (crafted to perform a benign but observable action such as writing a file or logging a message).
3. **Trigger Restoration:** Initiate an AJAX update so that `restore_from_cache()` is invoked for the affected component, which will unpickle the malicious payload.
4. **Observation:** Monitor the system (logs, file changes, etc.) for evidence that the payload executed, confirming the insecure unpickling behavior.
5. **Cleanup:** Remove any test artifacts created during the demonstration and reconfigure the cache backend or switch to a safer serialization mechanism.

---

## Vulnerability Name: Hardcoded Secret Key and Debug Mode Enabled in Production

**Description:**
The project’s configuration file (`example/project/settings.py`) contains a hardcoded secret key and an enabled debug mode:
```python
SECRET_KEY = "p6b$i%36e_xg%*ok+55@uc(h9)#g+2fj#p%7g#-@y8s6+10q#7"
DEBUG = True
ALLOWED_HOSTS = ["localhost"]
```
If an operator deploys this configuration to a publicly accessible production environment without overriding these values, an attacker may exploit the situation in two ways. First, the hardcoded secret key (which is used for cryptographic signing, cookie protection, CSRF tokens, and more) makes it possible to forge session cookies and tamper with signed data. Second, with `DEBUG` enabled, error pages will display detailed stack traces and configuration information that can help an attacker gain insight into the application’s inner workings.

**Impact:**
An attacker who discovers the secret key can craft forged tokens (such as session cookies or password reset tokens) to bypass authentication or escalate privileges. In addition, detailed error pages revealed by `DEBUG=True` may expose database configurations, file paths, and other sensitive internal details that could aid further attacks.

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**
- The default settings restrict `ALLOWED_HOSTS` to `"localhost"`, which offers some isolation during development.
- However, there is no enforcement that these settings be changed when deploying to a production environment.

**Missing Mitigations:**
- The application does not use environment variables or a secure configuration management system to set the `SECRET_KEY` and `DEBUG` settings dynamically in production.
- There is no mechanism to guarantee that `DEBUG` is disabled or that the secret key is rotated when deploying the application in a publicly available environment.

**Preconditions:**
- The same settings file is used for production deployment or overrides are not applied before deployment.
- The application is deployed to a publicly accessible instance, making it reachable by an external attacker.
- An external attacker is able to trigger server errors (for example, by sending malformed requests) and view detailed error pages.
- The application's configuration details are either disclosed through repository access or due to deployment misconfiguration.

**Source Code Analysis:**
1. In **`example/project/settings.py`**, the following lines are present without any conditional logic to secure them in production:
   ```python
   SECRET_KEY = "p6b$i%36e_xg%*ok+55@uc(h9)#g+2fj#p%7g#-@y8s6+10q#7"
   DEBUG = True
   ALLOWED_HOSTS = ["localhost"]
   ```
2. This hardcoding of the secret key combined with an enabled debug mode is acceptable only in a strictly controlled development environment, but if deployed as is in production, it exposes critical cryptographic material and detailed error output.

**Security Test Case:**
1. **Setup:** Deploy the application in an environment accessible over the internet using the provided settings (i.e., without overriding the hardcoded `SECRET_KEY` and without disabling `DEBUG`).
2. **Trigger Error:** Send a request (or deliberately cause an error) that triggers an exception in the application, causing Django to render its debug error page.
3. **Observation:** Verify that the error page displays sensitive internal information such as file paths, stack traces, and the hardcoded secret key.
4. **Forging Test:** Using the known secret key, attempt to craft a forged session cookie or tamper with a signed token (e.g., a password reset token) to demonstrate that cryptographic signing relies solely on publicly disclosed information.
5. **Cleanup:** After the demonstration, change the configuration to use secure practices (such as loading the secret key from an environment variable and setting `DEBUG=False`) and redeploy the application.

---
```

This list includes only vulnerabilities that are valid (not mitigated), have a high or critical rank, and are applicable in a publicly accessible production environment where an external attacker can trigger the vulnerabilities.
