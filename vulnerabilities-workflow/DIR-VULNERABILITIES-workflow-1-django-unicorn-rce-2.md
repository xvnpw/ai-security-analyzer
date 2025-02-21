- **Vulnerability Name:**
  Class Pollution via Dunder Attribute Injection in Component Initialization, Dynamic Updates, and Property Setters

- **Description:**
  The application accepts untrusted key–value pairs through several entry points:
  • When the unicorn template tag is used to instantiate a component,
  • When JSON payloads are sent to the “/message” endpoint (as demonstrated in tests such as _test_message.py_ and _test_set_property_from_data.py_), and
  • When helper functions such as `set_property_from_data()` update component properties.

  In each of these cases, the keys provided by the user are mapped directly—using Python’s built‑in `setattr()`—onto component objects without sufficient filtering. This approach does not reject keys that begin with double underscores (e.g. `__class__`, `__init__`, etc.). An attacker can therefore supply a JSON payload like:
  ```json
  {
    "id": "test123",
    "epoch": "<current-timestamp>",
    "data": {
      "__class__": "str"
    },
    "checksum": "<valid-checksum>",
    "actionQueue": []
  }
  ```
  When such a payload is processed, the component’s internal attributes are overwritten. Since key resolution and assignment occur both during instantiation and on later dynamic updates (via utility functions such as `set_property_from_data()`), an attacker can “pollute” the component’s internal state, changing its type or behavior in unintended ways. This can serve as a foundation for chaining further attacks—including remote code execution—if core security assumptions are subverted.

- **Impact:**
  • The integrity of a component is compromised when its critical attributes (including its class identity) can be modified.
  • Subsequent behaviors, methods, or even caches based on the component become unreliable, potentially allowing an attacker to bypass internal security checks.
  • In combination with other flaws, this may lead to arbitrary code execution and full remote compromise of the application.

- **Vulnerability Rank:**
  Critical

- **Currently Implemented Mitigations:**
  • The unicorn template tag (in `django_unicorn/templatetags/unicorn.py`) performs some initial filtering of reserved keywords.
  • Later, methods such as `_is_public()` during context construction filter the data for exposure purposes.
  • **However:** None of these defenses specifically reject or sanitize keys that begin with `"__"`, leaving the core issue unaddressed in both component instantiation and dynamic updates via the “/message” endpoint.

- **Missing Mitigations:**
  • The project should implement a sanitization step (or use a strict whitelist) to reject any untrusted key starting with `"__"`, applied both at component instantiation and during later state updates.
  • The utility functions (e.g. `set_property_from_data()`) need to validate keys before calling `setattr()` to ensure that only intended, safe properties are updated.

- **Preconditions:**
  • The attacker must be able to control parts of the application’s input (for instance, by manipulating the unicorn tag in a template or by sending crafted JSON to the “/message” endpoint).
  • The application must be using property-caching and dynamic update logic that maps these untrusted inputs directly onto a component’s attributes.

- **Source Code Analysis:**
  • In the unicorn template tag (located in `django_unicorn/templatetags/unicorn.py`), keyword arguments passed from the template are resolved and forwarded to the component initialization logic. These are not filtered specifically for dunder prefixes.
  • The “/message” endpoint (as exercised by tests in _test_message.py_) receives JSON payloads containing an “actionQueue” and “data” elements. Subsequently, helper functions (e.g. `set_property_from_data()`, seen in _test_set_property_from_data.py_) process these payloads by subsequently invoking `setattr(component, property_name, property_value)` without verifying whether `property_name` uses a reserved dunder pattern.
  • As every Python object inherently contains attributes such as `__class__`, an attacker’s maliciously supplied key (e.g. `"__class__"`) will be accepted and will override the state of the component.

- **Security Test Case:**
  1. **Preparation:**
     • Create or identify a test component (such as one subclassing `UnicornView`) whose type and behavior are well known.
  2. **Crafting Payload:**
     • Construct a JSON payload that mimics a valid “/message” request but includes a dunder-prefixed key. For example:
       ```json
       {
         "id": "test123",
         "epoch": "<current-timestamp>",
         "data": {
           "__class__": "str"
         },
         "checksum": "<valid-checksum>",
         "actionQueue": []
       }
       ```
  3. **Execution:**
     • Send the crafted payload to the `/message/<component_identifier>` endpoint (using curl, Postman, or an automated test client).
  4. **Verification:**
     • Retrieve the updated component (either through a follow-up request or via a diagnostic method) and inspect its `__class__` or other critical dunder attributes.
     • Confirm that the component’s internal state has been altered (for example, if its type has changed from the expected to `str`, or if behavior diverges from the pre-update norms).
  5. **Documentation:**
     • Record any observed anomalies which confirm successful class pollution, indicating the vulnerability’s presence.

---

- **Vulnerability Name:**
  Remote Code Execution via Unsafe Pickle Deserialization in Component Caching

- **Description:**
  In order to store the complete component tree (including nested relationships and callbacks) efficiently, the framework serializes component instances using Python’s pickle module. The serialized data is stored in the Django cache under keys such as `"unicorn:queue:<component_id>"`. When a component is later rehydrated, the cached data is deserialized using `pickle.loads()`.

  As pickle deserialization is inherently unsafe—since it can execute arbitrary code embedded within a pickle stream—and because there is no cryptographic signing or integrity verification performed on the cached data, an attacker who manages to write to or otherwise manipulate the cache datastore (for example, due to a misconfigured Redis or memcached server that is exposed to the Internet) can supply a malicious pickle payload. When this payload is later deserialized, arbitrary code may be executed on the server.

- **Impact:**
  • An attacker with the ability to manipulate the cache can execute arbitrary code on the server, leading to full system compromise.
  • Data exfiltration, system manipulation, and unauthorized actions may occur as a result of such an exploit.

- **Vulnerability Rank:**
  Critical

- **Currently Implemented Mitigations:**
  • The framework provides an option to disable component serialization (for example, when using a “dummy” cache backend).
  • The documentation instructs users to properly secure their cache backend so that only trusted parties have access.
  • **However:** No in-code mechanism (such as digital signatures or HMAC verification) is implemented to ensure the integrity of the data before calling `pickle.loads()`.

- **Missing Mitigations:**
  • Introduce cryptographic integrity checks (for example, signing the serialized payload) so that any tampered data can be detected and rejected before deserialization.
  • Consider replacing pickle-based serialization with a safer alternative or restrict its use exclusively to trusted environments.
  • Enforce strict access controls and network-level protections to ensure that the cache backend is not accessible to external attackers.

- **Preconditions:**
  • Component serialization must be enabled (as controlled by the `UNICORN["SERIAL"]["ENABLED"]` configuration setting or equivalent).
  • The cache backend (defined via the project’s caching configuration) must be misconfigured or exposed to allow unauthorized writes.
  • An attacker must be able to inject or replace a valid cache entry with a malicious pickle payload.

- **Source Code Analysis:**
  • In `django_unicorn/views/__init__.py`, the function `_handle_component_request()` checks a setting (via `get_serial_enabled()`) to determine whether to serialize the component.
  • Upon serialization, the component state is stored in the cache under a key like `"unicorn:queue:<component_id>"`.
  • Later, the function `_handle_queued_component_requests()` retrieves the serialized state and calls `pickle.loads()` to rehydrate the component, without performing any integrity checks.
  • With no signing or verification in place, any modification to the cache (for instance, by an external attacker) results in a direct, uncontrolled execution of the maliciously crafted pickle data.

- **Security Test Case:**
  1. **Environment Setup:**
     • Configure the Django cache backend (for example, Redis) in a manner that makes it accessible from an external machine (simulate a misconfiguration).
  2. **Trigger Serialization:**
     • Initiate a normal component operation that will result in the component being serialized and cached (note the cache key, e.g., `"unicorn:queue:<component_id>"`).
  3. **Inject Malicious Payload:**
     • Using an external tool or script, overwrite the cache entry for the identified key with a malicious pickle payload crafted to perform a recognizably harmful action (for example, writing a file to disk or executing a shell command).
  4. **Trigger Deserialization:**
     • Cause the application to rehydrate the component (for example, by sending a subsequent message request that forces the component’s state to be reloaded).
  5. **Verification:**
     • Observe whether the malicious payload is executed (for example, by verifying the presence of the file or by monitoring for command execution), thus confirming that arbitrary code execution has been achieved.
  6. **Documentation:**
     • Record the steps and the resulting exploit to demonstrate that the unsafe deserialization vulnerability is present.
