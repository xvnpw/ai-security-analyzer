- **Vulnerability Name:** Unsafe Deserialization of Cached Components via Pickle
  **Description:**
  • *What happens:* When a Unicorn component is rendered for the first time its entire state (including properties, relationships, and form data) is serialized using Python’s built‑in pickle module and stored in the Django cache. On later requests the component is restored by unpickling the cached data.
  • *How it can be triggered:*
  1. If an attacker can access (or poison) the project’s cache backend (for example, when Redis or memcached is misconfigured and exposed to untrusted networks), they can inject a malicious pickle payload under a predictable cache key (e.g. “unicorn:component:&lt;component_id&gt;”).
  2. When a legitimate user next triggers a component re‑render, the system unpickles the directed value and executes the attacker’s payload.
  **Impact:**
  • This can lead to remote code execution (RCE) on the server hosted Django application, giving the attacker the ability to execute arbitrary Python code and potentially compromise the entire system.
  **Vulnerability Rank:** Critical
  **Currently Implemented Mitigations:**
  • The project relies on Django’s caching configuration and assumes that production caches are securely configured. No additional integrity checks or safe‐serialization alternatives are applied.
  **Missing Mitigations:**
  • No signature or integrity verification is performed on the cached pickle data.
  • There is no migration to a safe serialization format (for example, JSON‑based serialization) for critical component state.
  **Preconditions:**
  • The cache backend must be accessible by an attacker (for example, a misconfigured or publicly accessible Redis/memcached instance).
  **Source Code Analysis:**
  • In `django_unicorn/cacher.py`, when a component is rendered for the first time, its state is serialized with `pickle.dumps()` and written to the cache under a key such as:
  `component_cache_key = f"unicorn:component:{component_id}"`
  • On subsequent renders, the cached data is obtained and unpickled using `pickle.loads()` without any additional checks, which means that if the cache is poisoned, an attacker’s payload will be executed.
  **Security Test Case:**
  • **Setup:** In a controlled lab environment, configure the Django cache (e.g. Redis or memcached) so it is accessible by an attacker account or simulate an attacker’s connection to the cache.
  • **Steps:**
  1. Identify a valid component id by triggering a component render and noting the cache key format.
  2. Using a cache client, inject a malicious pickle payload under the key, for example: `unicorn:component:<component_id>`.
  3. Trigger a normal component re‑render on the application (e.g. by refreshing the page).
  • **Expected Result:** The malicious payload contained in the injected pickle is unpickled and its code is executed on the server, thereby compromising the system.

---

- **Vulnerability Name:** Sensitive Data Exposure through Full Django Model Serialization
  **Description:**
  • *What happens:* When a component binds a Django model to a template (using the `unicorn:model` directive), the entire model instance is serialized into JSON and injected into the rendered HTML. By default every public field is included (via the helper `_get_model_dict()` in `django_unicorn/serializer.py`).
  • *How it can be triggered:*
  1. A developer binds a Django model (which might include sensitive information such as internal statuses, personal identifiers, or security tokens) to a Unicorn component without filtering out sensitive attributes.
  2. When the component renders, the model is serialized with all of its fields and included in the HTML source code—visible either through “view source” or browser developer tools.
  **Impact:**
  • Exposure of sensitive internal or personal data can lead to privacy breaches, compliance issues, or facilitate further attacks if the leaked data is used elsewhere in the system.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  • The documentation warns developers that full model serialization exposes all fields by default and advises configuring exclusions (e.g. via `Meta.exclude` or `Meta.javascript_exclude`).
  **Missing Mitigations:**
  • There is no automatic filtering of sensitive fields before serialization.
  • No secure-by-default mechanism is implemented to prevent sensitive fields from being serialized.
  **Preconditions:**
  • The developer uses model binding via `unicorn:model` without explicitly excluding sensitive fields.
  **Source Code Analysis:**
  • In `django_unicorn/serializer.py`, the `_get_model_dict(model)` function iterates over all fields defined in the model (using `model._meta.fields` and many‑to‑many relationships) and creates a dictionary that is then embedded in the HTML.
  • Because this process occurs by default, unless the developer opts out via component meta options, all field data—including sensitive data—will be exposed in the rendered page.
  **Security Test Case:**
  • **Setup:** Create a Django model that includes one or more sensitive fields (e.g. “password” or “secret_info”) and bind it to a Unicorn component using the standard `unicorn:model` attribute without exclusions.
  • **Steps:**
  1. Render the component on a test page.
  2. View the page’s HTML source or use developer tools to locate the JSON payload (typically embedded as `unicorn:data`).
  • **Expected Result:** The serialized JSON—inclusive of sensitive fields—will be visible in the page source, proving that by default all fields are exposed.

---

- **Vulnerability Name:** Mass Assignment Vulnerability via Unvalidated Component Data Binding
  **Description:**
  • *What happens:* When a client sends a JSON payload to the `/message/<component_name>/` endpoint, the framework processes the request by calling helper functions such as `set_property_from_data()` (in `django_unicorn/views/utils.py`) and `set_property_value()` (in `django_unicorn/views/action_parsers/utils.py`). These functions simply check that an attribute exists on the component using `hasattr()` and then call `setattr()` to update the attribute without further validation.
  • *How it can be triggered:*
  1. An attacker (or a misbehaving client) crafts a JSON payload that includes keys corresponding to internal or “private” attributes (for example, properties starting with an underscore or special names like `__class__`).
  2. Upon processing the payload, the framework blindly updates these attributes using `setattr()`, thereby altering the component’s internals in unintended ways.
  **Impact:**
  • Unauthorized updates to internal attributes can allow an attacker to modify critical component behavior. For example, changing internal states could facilitate privilege escalation, bypass of business logic, or even set the stage for remote code execution if critical methods are overridden.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  • The current implementation only verifies attribute existence using `hasattr()` and does not filter out “private” attributes (those beginning with an underscore) or special “dunder” names.
  **Missing Mitigations:**
  • No allowlist or schema validation exists to restrict which properties may be updated through client data.
  • The framework should ignore or reject keys that begin with an underscore or match special names unless explicitly allowed.
  **Preconditions:**
  • The attacker must have the ability (for example, via a valid CSRF token or authenticated session) to send POST requests to the `/message/<component_name>/` endpoint.
  • The component must allow state updates via incoming JSON without restrictions on property names.
  **Source Code Analysis:**
  • In `django_unicorn/views/utils.py`, the `set_property_from_data()` function iterates over keys supplied in the JSON payload. After simply verifying with `hasattr(component, key)`, it retrieves the current value and then updates it via `setattr(component, key, value)`.
  • For instance, if the payload contains a key such as `"__class__"`, the code executes:
  `set_property_from_data(component, "__class__", malicious_value)`
  which could change the component’s type or internal state unexpectedly.
  **Security Test Case:**
  • **Setup:**
  – Deploy the Django‑Unicorn application in a test environment with valid CSRF protection or authentication.
  – Identify a component (for example, one from the provided fake components).
  • **Steps:**
  1. Craft a JSON payload with the “data” object including an internal attribute key (for instance:
    `{ "data": { "__class__": "malicious_value", "name": "NormalName" }, "id": "<component_id>", "epoch": "<timestamp>", "checksum": "<valid_checksum>" }`
    ).
  2. Submit the payload in a POST request to the `/message/<component_name>/` endpoint.
  3. After the request is processed, fetch the component’s state (either via a subsequent GET request or by observing behavior/logs) and inspect whether attributes such as `__class__` have been modified.
  • **Expected Result:**
  Critical internal attributes (e.g. `__class__`) should remain unchanged. If the vulnerability is present, the internal attribute will be overwritten with the malicious value, confirming that unsanitized mass assignment is possible.

---

- **Vulnerability Name:** Weak Checksum Verification on Component Data
  **Description:**
  • *What happens:* The `/message/<component_name>/` endpoint expects incoming JSON messages to include a `checksum` computed over the component’s data payload. The checksum is generated using the helper function (e.g. `generate_checksum(str(data))`) and then validated on receipt.
  • *How it can be triggered:*
  1. An attacker who can intercept or observe a valid request determines the algorithm (which simply converts the data to a string and computes a hash) used for generating the checksum.
  2. The attacker modifies the payload data (for example, to change sensitive properties) and then recomputes the checksum locally using the same algorithm.
  3. The attacker sends the modified payload with the valid checksum, bypassing the integrity check.
  **Impact:**
  • Bypassing the checksum allows an attacker to tamper with the component’s state without detection. This could be leveraged to abuse the mass assignment vulnerability, modify internal state arbitrarily, and ultimately escalate privileges or cause unintended behavior in the application.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  • The endpoint verifies that a `checksum` is present and that it matches a newly computed value from the incoming data.
  • Requests with missing or mismatched checksum are rejected (as demonstrated in tests like “test_message_bad_checksum”).
  **Missing Mitigations:**
  • The checksum generation does not incorporate a secret key or use a keyed-hash mechanism (such as HMAC), making it entirely predictable by an attacker.
  • There is no mechanism to prevent an attacker from recomputing and substituting a valid checksum after modifying the payload.
  **Preconditions:**
  • The attacker must have access to a valid component interaction (for instance, by authenticating or by exploiting CSRF/CORS weaknesses) and be able to capture or observe a legitimate JSON payload.
  • The underlying `generate_checksum` function must be using a non-keyed, predictable algorithm.
  **Source Code Analysis:**
  • Test cases (for example, in `test_setter` and `test_message_*` files) import and use `generate_checksum` by passing either the data dictionary or its string representation.
  • The same checksum algorithm is used on both the client (or test harness) and the server to verify integrity. Since it lacks any secret or salt, an attacker can mimic the checksum calculation.
  **Security Test Case:**
  • **Setup:** Capture a legitimate JSON payload sent to the `/message/<component_name>/` endpoint (ensure you have valid authentication/CSRF tokens as necessary).
  • **Steps:**
  1. Note the structure of the payload and the checksum value computed from the original data.
  2. Modify one or more sensitive properties in the “data” object.
  3. Locally recompute the checksum (using the same algorithm, for example by calling `generate_checksum(str(modified_data))`).
  4. Replace the original checksum with the recomputed valid checksum and send the modified payload to the endpoint.
  5. Observe whether the server accepts the tampered payload and applies the changes.
  • **Expected Result:** The server accepts the modified payload because the checksum validation passes with the attacker‑computed valid checksum, confirming that the checksum mechanism can be bypassed.

---

- **Vulnerability Name:** Information Disclosure via Dynamic Component Loading Errors
  **Description:**
  • *What happens:* The framework dynamically loads component modules and classes based on the component name provided in the URL (for example, `/message/<component_name>/`). When a component cannot be found or loaded correctly, exceptions such as `ComponentModuleLoadError` or `ComponentClassLoadError` are raised. These errors include detailed diagnostic information such as the names of the modules or classes attempted and their expected file locations.
  • *How it can be triggered:*
  1. An external attacker sends a request to the `/message` endpoint using non‑existent or malformed component names (e.g. with dashes, dots, or arbitrary strings).
  2. The framework attempts to load the component, fails, and throws an error that includes internal module paths and class names.
  **Impact:**
  • Detailed error messages can leak information about the application’s internal structure—including module names, file paths, and class names—which can aid an attacker in mapping the application and planning more targeted attacks.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  • The framework does check for the existence of a component and will raise an error if it cannot be loaded.
  • However, in several test cases (for example, `test_message_component_module_not_loaded` and `test_message_component_class_not_loaded`), the exceptions include granular details about the internal lookup process.
  **Missing Mitigations:**
  • The error handling does not sanitize or abstract out internal filenames, module paths, or class names before returning errors to the client.
  • In production, detailed error messages should be suppressed or replaced with generic error responses to prevent information leakage.
  **Preconditions:**
  • The application must be configured (or inadvertently left in debug mode) to expose detailed error information to clients.
  • The attacker must be able to send arbitrary requests to the dynamic component loading endpoint.
  **Source Code Analysis:**
  • In tests such as `test_message_component_module_not_loaded` and `test_message_component_class_not_loaded`, requests with malformed component names trigger exceptions (e.g. `ComponentModuleLoadError` or `ComponentClassLoadError`).
  • The exception messages and their associated properties (such as the `locations` attribute listing candidate module paths) reveal how the framework resolves component names.
  **Security Test Case:**
  • **Setup:** Deploy a publicly accessible instance of the application with debug mode enabled or with unsanitized error reporting.
  • **Steps:**
  1. Send a POST request to the `/message/<malformed-component-name>/` endpoint using a valid JSON payload (include required fields such as “data”, “id”, “epoch”, and “checksum”). Examples might include names like “test-with-dash” or “test.dot”.
  2. Capture the JSON error response or HTTP error output.
  3. Inspect the error message for detailed internal module paths, class names, or file locations.
  • **Expected Result:** The response should not include any internal diagnostic details. If internal structure information is leaked, the vulnerability is confirmed.
