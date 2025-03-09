- **Vulnerability Name:** Insecure Deserialization via Pickle in Component Caching
  **Description:**
  The Unicorn framework caches component state by pickling entire component view instances. In the file “django_unicorn/cacher.py,” the class `CacheableComponent` calls `pickle.dumps(component)` when caching and later invokes `pickle.loads()` within the function `restore_from_cache` to rehydrate the component. An external attacker who is able to tamper with the underlying Django cache (for example, by exploiting a misconfigured Redis or Memcached instance that is exposed to untrusted networks) can inject a crafted pickle payload. When the framework deserializes this payload, arbitrary code execution can occur on the server.
  **Impact:**
  *Remote code execution* — The attacker may run arbitrary Python code with the privileges of the Unicorn process. This may lead to a full server compromise, data exfiltration, or service disruption.
  **Vulnerability Rank:** Critical
  **Currently Implemented Mitigations:**
  - The project currently assumes that the Django cache backend is secure and accessible only on internal networks (for example, using local-memory cache or a well‐secured Redis/Memcached instance).
  **Missing Mitigations:**
  - There is no cryptographic signing or integrity checking of pickled data before deserialization.
  - A safer serialization format (such as JSON for component state, where possible) is not used.
  **Preconditions:**
  - The attacker must be able to inject or modify the cached pickle data (for example, via a misconfigured or publicly accessible cache backend).
  **Source Code Analysis:**
  - In “django_unicorn/cacher.py”, the `CacheableComponent.__enter__()` method serializes the component via `pickle.dumps(component)`.
  - Later, `restore_from_cache()` passes the cached data directly into `pickle.loads()` without performing any integrity or signature validation.
  - No sandboxing or limited deserialization mechanism is applied, so any malicious payload will be fully executed.
  **Security Test Case:**
  - **Setup:** Configure a test cache backend (or simulate it) that is accessible for external manipulation.
  - **Test Steps:**
    1. Instantiate a Unicorn component and trigger its caching routine (for example, by sending an AJAX request that causes its state to be cached).
    2. Access the cache store (or simulate a tampering hook) and overwrite the serialized value (keyed under “unicorn:component:<component_id>”) with a malicious pickle payload that, when deserialized, performs an observable action (for example, writing a file or setting a flag).
    3. Trigger the component’s restoration from cache (for instance, via a subsequent AJAX call that causes state rehydration).
    4. Verify that the malicious payload’s effect has taken place (such as the presence of the file or flagged marker).
  - **Expected Result:** The test should demonstrate that the tampered payload is executed, confirming the vulnerability.

- **Vulnerability Name:** Arbitrary Attribute Injection via Unsanitized Property Updates
  **Description:**
  Unicorn allows updating component properties over AJAX by accepting JSON payloads that specify property names (which may use dotted notation for nested attributes) and values. In the file “django_unicorn/views/action_parsers/utils.py” the function `set_property_value` uses simple string splitting and then uses Python’s built‑in `setattr()` to update component attributes without validating whether the given property name is approved for update. Although the framework filters which attributes appear in the rendered component “context” via an internal “_is_public” check, this filtering is not applied when processing incoming update data—allowing an attacker to manually supply keys that correspond to private or internal attributes.
  **Impact:**
  *State tampering and potential privilege escalation* — An attacker (for example, leveraging CSRF together with valid session cookies) can submit a crafted JSON payload that updates internal attributes (including those beginning with an underscore or those reserved for internal logic). This may allow bypassing internal checks, altering component behavior and potentially escalating privileges.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - When the Unicorn JSON “context” is built for rendering the component, only attributes passing the “_is_public” filter are included. However, this filter is applied only when serializing values for the frontend and not to incoming update requests.
  **Missing Mitigations:**
  - There is no server‑side verification (such as a whitelist) to reject updates to non‑public attributes.
  - No additional strict filtering is applied to block property updates that use dot‑notation to reach nested private or reserved attributes.
  **Preconditions:**
  - The attacker must be able to send an AJAX (or forged) POST request to the Unicorn message endpoint with valid CSRF tokens (or via a CSRF attack against an authenticated session).
  **Source Code Analysis:**
  - In “django_unicorn/views/action_parsers/utils.py”, the function `set_property_value` extracts the property name from the payload (which may include dots for nested attributes) and then directly calls `setattr()` on the component for each level of the attribute hierarchy.
  - No check is made during property update against the whitelist of public attributes.
  - The vulnerability exists because the frontend filtering (via the “_is_public” function) is used only when initially generating component output—not when processing incoming data.
  **Security Test Case:**
  - **Setup:** Deploy a Unicorn component that defines an internal attribute (for example, `_secret`) that is not exposed in the rendered public context.
  - **Test Steps:**
    1. From an external client (with valid CSRF credentials), craft a JSON POST request to the Unicorn message endpoint, including in the “data” field an extra key such as `"_secret": "malicious_value"`.
    2. Also include an action (for example, using syncInput) that causes the component to process both expected public attributes and the injected attribute.
    3. Submit the request and observe the updated state of the component (either by examining the returned JSON data or the rendered HTML).
    4. Check whether the private attribute `_secret` has been set to “malicious_value.”
  - **Expected Result:** In a secure implementation the update should either reject or ignore any attempt to change private attributes. If the vulnerability is present, the test reveals that the internal attribute has been updated with the attacker‑supplied value.
