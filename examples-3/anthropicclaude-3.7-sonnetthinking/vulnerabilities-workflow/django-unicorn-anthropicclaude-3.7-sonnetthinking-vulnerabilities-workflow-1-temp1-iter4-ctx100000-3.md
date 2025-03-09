# Vulnerabilities in Django-unicorn

After analyzing the criteria and the provided vulnerabilities, I've determined the following high-severity issues that could be exploited by an external attacker targeting a publicly available instance:

## 1. Insecure Deserialization using Python's pickle Module

**Vulnerability Name**: Insecure Deserialization

**Description**:
Django-unicorn uses Python's `pickle` module for component serialization/deserialization in the caching mechanism. This is evident in `django_unicorn/cacher.py` where components are pickled and unpickled. When a component is restored from cache, `pickle.loads()` is used to deserialize the data:

```python
try:
    attribute_value = pickle.loads(pickled_value)  # noqa: S301
    self._set_property(attribute_name, attribute_value)
except TypeError:
    logger.warn(f"Resetting '{attribute_name}' attribute failed because it could not be constructed.")
    pass
```

If an attacker can manipulate component attributes that get stored in the cache (either by crafting a malicious payload that ends up as a component attribute or by compromising the cache storage), and then trigger the unpickling of that data, they could execute arbitrary code on the server.

**Impact**:
Remote code execution on the server hosting the Django application. An attacker could execute arbitrary Python code with the same privileges as the web application, potentially leading to complete server compromise, data theft, or service disruption.

**Vulnerability Rank**: Critical

**Currently Implemented Mitigations**:
The framework tries to use validation and checksums to prevent tampering with component data, but these mitigations are insufficient if the cache storage itself can be compromised or if there are other ways to inject malicious data into component attributes.

**Missing Mitigations**:
1. Use a safer serialization format like JSON
2. If pickle must be used, implement strict validation of unpickled objects
3. Add pattern matching or schema validation for unpickled data

**Preconditions**:
1. The application must use the component caching feature
2. An attacker must be able to influence what gets stored in a component's attributes or compromise the cache storage
3. The attacker must be able to trigger the unpickling of their specifically crafted data

**Source Code Analysis**:
The vulnerability exists in `django_unicorn/cacher.py`. When `restore_from_cache` is called, it retrieves a cached component and unpickles it:

```python
def restore_from_cache(component_cache_key: str, request: Optional[HttpRequest] = None) -> "django_unicorn.views.UnicornView":
    """
    Gets a cached unicorn view by key, restoring and getting cached parents and children
    and setting the request.
    """
    cache = caches[get_cache_alias()]
    cached_component = cache.get(component_cache_key)
    # ...
```

The cached_component is retrieved without validation and used directly. If an attacker could place a malicious pickled object in the cache, it would be executed when unpickled.

The components are initially serialized in `cache_full_tree`:

```python
def cache_full_tree(component: "django_unicorn.views.UnicornView"):
    root = component
    # ...
    with CacheableComponent(root) as caching:
        for _component in caching.components():
            cache.set(_component.component_cache_key, _component)
```

When a user interacts with a component, their input could potentially be stored as an attribute in the component, then pickled and cached. Later, when the component is restored from cache, the malicious input would be unpickled and potentially execute code.

**Security Test Case**:
1. Identify a component with user input fields that is cached
2. Create a malicious pickle payload that executes arbitrary code (e.g., to make an HTTP request to an attacker-controlled server)
3. Find a way to inject this payload into a component attribute (e.g., through a form field or component method parameter)
4. Trigger an action that causes the component to be cached
5. Trigger another action that causes the component to be restored from cache
6. Observe if the malicious code is executed

## 2. Weak Checksum Validation for Component Data Integrity

**Vulnerability Name**: Insufficient Cryptographic Strength in Component Checksums

**Description**:
Django-unicorn uses checksums to ensure the integrity of component data between the server and client. However, in `django_unicorn/utils.py`, these checksums are truncated to only 8 characters:

```python
checksum = hmac.new(
    str.encode(settings.SECRET_KEY),
    data_bytes,
    digestmod="sha256",
).hexdigest()
checksum = shortuuid.uuid(checksum)[:8]  # Truncated to only 8 characters
```

While HMAC-SHA256 is a strong algorithm, truncating the result to only 8 characters significantly reduces the security. This creates a much smaller space of possible checksums, making it feasible for an attacker to brute force or find collisions. The test files confirm this implementation, with several tests in `test_hash.py` and `test_message.py` validating this checksum behavior.

**Impact**:
An attacker could potentially forge valid checksums, allowing them to tamper with component data. This could lead to unauthorized actions, data manipulation, or potentially even injection attacks if the tampered data is used in sensitive operations.

**Vulnerability Rank**: High

**Currently Implemented Mitigations**:
The use of HMAC with Django's SECRET_KEY as the basis for the checksum is good practice, but the truncation undermines this security measure.

**Missing Mitigations**:
1. Use the full HMAC-SHA256 output or at least a larger portion (32+ characters)
2. Implement additional validations on component data

**Preconditions**:
1. An attacker needs to understand how the checksum system works
2. The attacker needs to be able to capture and modify requests between client and server

**Source Code Analysis**:
The vulnerability is in `django_unicorn/utils.py` in the `generate_checksum` function. The test files (especially `test_hash.py`) confirm that checksums are used extensively throughout the application to validate component data integrity.

From `test_message.py`, we can see that the application does check for missing or invalid checksums:

```python
def test_message_no_checksum(client):
    data = {
        "data": {},
        "id": str(uuid4()),
        "epoch": time.time(),
    }
    response = post_json(client, data, url="/message/test-message-no-checksum")

    assert_json_error(response, "Missing checksum")


def test_message_bad_checksum(client):
    data = {
        "data": {},
        "checksum": "asdf",
        "id": str(uuid4()),
        "epoch": time.time(),
    }
    response = post_json(client, data, url="/message/test-message-bad-checksum")

    assert_json_error(response, "Checksum does not match")
```

However, with only 8 characters, there are only 16^8 = 4,294,967,296 possible checksums. While this seems large, it's within the range of brute-force attacks, especially if an attacker can make automated requests.

**Security Test Case**:
1. Capture an AJAX request sent by a Django-unicorn component
2. Modify the component data in the request
3. Generate multiple random checksums (up to a few million) and try them with the modified component data
4. If a valid checksum is found (server accepts the request), the vulnerability is confirmed
5. Alternatively, analyze multiple legitimate checksums to look for patterns or collision opportunities
