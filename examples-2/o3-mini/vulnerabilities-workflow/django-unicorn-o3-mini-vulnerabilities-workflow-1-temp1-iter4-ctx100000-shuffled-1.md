# Updated Vulnerabilities List

Below is the final list of vulnerabilities that are valid, not already mitigated, and have a vulnerability rank of at least **high**. These vulnerabilities assume an external attacker attempting to trigger issues on a publicly available instance of the application.

---

## 1. Insecure Deserialization via Pickle in Component Caching Mechanism

- **Description:**
  Within the component class (specifically in the method that caches resettable public attributes), mutable public attributes (for example, instances of models or custom fields) are serialized with Python’s built‑in `pickle.dumps` and later restored with `pickle.loads` when the component resets. If an attacker is able to tamper with the caching backend (for instance, if a remote Redis or Memcached backend is exposed without sufficient safeguards), they can inject a malicious pickle payload that will execute arbitrary code upon deserialization.

- **Impact:**
  An attacker who controls or can modify the cache data can force the server to deserialize attacker‑controlled data. This can lead to remote code execution and complete system compromise.

- **Vulnerability Rank:**
  **Critical**

- **Currently Implemented Mitigations:**
  The caching functions assume that the cache (for example, Django’s in‑memory cache or a properly secured remote cache) is configured correctly. In many development settings the default in‑memory cache is used, which is not exposed over the network.

- **Missing Mitigations:**
  There is no explicit signing or verification of the pickle payloads. A safer approach would be to:
  - Use a JSON‑based serializer for public state, or
  - Cryptographically sign the payload (for example, with an HMAC using the `SECRET_KEY`) so that tampered cache entries are detectable.

- **Preconditions:**
  - An attacker must be able to write to or manipulate the Django cache backend (for example, when a remote Redis/Memcached instance is misconfigured).
  - The vulnerable pickled data is later re‑deserialized (e.g. when the component resets).

- **Source Code Analysis:**
  1. In `django_unicorn/components/unicorn_view.py`, when iterating over public attributes in the method (such as `_set_resettable_attributes_cache`), mutable objects are pickled with:
     ```python
     self._resettable_attributes_cache[attribute_name] = pickle.dumps(attribute_value)
     ```
  2. Later, in the component’s `reset()` method, the values are restored via:
     ```python
     attribute_value = pickle.loads(pickled_value)
     ```
  3. No additional integrity check or signature is applied to the serialized data.

- **Security Test Case:**
  1. Configure your Django application to use a remote cache backend (like Redis or Memcached) that is not secured behind a firewall or authentication.
  2. Identify a valid component instance and locate its cache key (for example, `"unicorn:component:<component_id>"`).
  3. Using an external tool or direct cache connection, overwrite the cache entry with a crafted malicious pickle payload (for example, a payload that executes a harmless dummy action such as writing to a file or logging a message).
  4. Trigger the component’s reset function (for instance, by issuing a POST to the `/message/` endpoint with a reset action) and observe whether the payload is deserialized and its side effect is executed.
  5. A successful attack will demonstrate remote code execution via insecure deserialization.

---

## 2. Insecure Dynamic Module Import via Component Name Parameter

- **Description:**
  The framework dynamically constructs module and class names based on the `component_name` URL parameter (typically through the `/message/<component_name>` endpoint). Although the parameter is partially constrained by a regex (allowing only alphanumeric characters, underscores, dashes, dots, and slashes), an attacker may supply a crafted name that, combined with overly permissive settings (such as an unsanitized `UNICORN["APPS"]` list), causes the dynamic importer to locate and load unintended modules. This might allow an attacker to instantiate components not meant to be exposed externally.

- **Impact:**
  Instantiating unintended or internal components could expose sensitive functionality or internal behaviors. In extreme cases, if the loaded module exposes dangerous operations, this could lead to arbitrary code execution.

- **Vulnerability Rank:**
  **High**

- **Currently Implemented Mitigations:**
  - The URL parameter `component_name` is forced to match the regex `[\w/\.-]+`.
  - The candidate module locations are built using the developer‑controlled setting `UNICORN["APPS"]`, which in theory narrows down the search paths.

- **Missing Mitigations:**
  - No explicit whitelist is enforced for allowed component names.
  - The dynamic import logic lacks an additional layer of sanitization or restrictiveness to prevent an attacker from forcing the import of modules outside the intended scope.

- **Preconditions:**
  - The attacker must be able to supply arbitrary values for the `component_name` parameter via the public `/message/` endpoint.
  - The configuration under `UNICORN["APPS"]` must be set in a way that inadvertently allows access to unintended modules.

- **Source Code Analysis:**
  1. In `django_unicorn/components/unicorn_view.py`, the function `get_locations(component_name: str)` processes the component name by applying naming conversions.
  2. It then iterates over entries provided by `UNICORN["APPS"]` to build candidate module paths.
  3. The approach relies solely on the regex constraint and configuration; it does not further verify that the final resolved module is among an approved list.

- **Security Test Case:**
  1. In a staging environment, configure `UNICORN["APPS"]` to a less restrictive value or use the default.
  2. Craft a POST request to `/message/<component_name>` where `<component_name>` is set to a name resembling an internal or fully‑qualified module name (for example, `"internal.secret_module"`).
  3. Examine the response: if the system loads and instantiates the unintended module (or returns detailed error messages that confirm the module’s identity), then the dynamic module import remains insecure.

---

## 3. Detailed Error Message Disclosure in AJAX Responses

- **Description:**
  The view’s error handling decorator (as seen in `django_unicorn/views/__init__.py`) catches exceptions such as `UnicornViewError` and `AssertionError` and returns a JSON response containing the full error string in the `"error"` field. This detailed error output may inadvertently expose internal structures, including module paths, class names, and other sensitive implementation details.

- **Impact:**
  An attacker who purposely triggers errors (for example, by sending malformed requests) can obtain information that aids in further attacks (such as those exploiting the dynamic import or deserialization vulnerabilities).

- **Vulnerability Rank:**
  **High**

- **Currently Implemented Mitigations:**
  There is no sanitization of error messages sent to the client. The full exception string is included directly in the JSON response.

- **Missing Mitigations:**
  - Errors should be logged server-side while returning a generic error message (e.g. “An error occurred. Please try again later.”) in the client response to avoid revealing sensitive internals.

- **Preconditions:**
  - The attacker must be able to send AJAX POST requests (for example, through CSRF in an authenticated session) that trigger exceptions in the Unicorn component processing.

- **Source Code Analysis:**
  1. In `django_unicorn/views/__init__.py`, the error-handling decorator wraps the view function and catches specific exceptions:
     ```python
     except UnicornViewError as e:
         return JsonResponse({"error": str(e)})
     except AssertionError as e:
         return JsonResponse({"error": str(e)})
     ```
  2. This direct inclusion of `str(e)` in the response payload discloses internal error information to the client.

- **Security Test Case:**
  1. Create a POST request to `/message/<component_name>` with deliberately malformed data designed to trigger an exception (e.g. missing required fields or providing invalid data types).
  2. Examine the response to verify whether the `"error"` field contains detailed internal error information (such as internal paths, assertion messages, or other debug information).
  3. If detailed error messages are exposed instead of a generic message, the vulnerability is confirmed.

---

## 4. Template Path Traversal in Public Template Rendering

- **Description:**
  The view function `template` in the file `example/www/views.py` builds the template file path by directly interpolating the `name` parameter from the request into a string (e.g. `f"www/{name}.html"`) without proper validation or sanitization. An attacker can supply traversal characters (such as `"../"`) as part of `name` to manipulate the file path.

- **Impact:**
  An attacker may force the application to render templates that were not intended for public view. This can lead to exposure of sensitive template content, internal configuration details, or provide further information that aids additional attacks.

- **Vulnerability Rank:**
  **High**

- **Currently Implemented Mitigations:**
  The view includes a try/except block that catches `TemplateDoesNotExist` and raises an HTTP 404 error when a template cannot be found.

- **Missing Mitigations:**
  - There is no validation or sanitization of the `name` parameter to ensure it does not contain path traversal sequences.
  - The implementation should use secure path joining functions or Django’s safe template lookup utilities to normalize and validate the template path.

- **Preconditions:**
  - The endpoint mapped to the `template` view must be publicly accessible.
  - An attacker must be able to supply arbitrary values for the `name` parameter (e.g., via a GET parameter in the URL).

- **Source Code Analysis:**
  1. In `example/www/views.py`, the `template` function is implemented as:
     ```python
     def template(request, name):
         try:
             return render(request, f"www/{name}.html", context={"example": "test"})
         except TemplateDoesNotExist:
             raise Http404
     ```
  2. The code directly concatenates the value of `name` with `"www/"` and `".html"` without input sanitization. For example, if `name` is `"../secret"`, the resolved path becomes `"www/../secret.html"`, potentially accessing a template outside the intended folder.

- **Security Test Case:**
  1. Using a tool like cURL or a web browser, send a GET request to the endpoint corresponding to the `template` view with a crafted `name` parameter that includes directory traversal input (for example: `/template/../settings`).
  2. Observe the HTTP response:
     - If the application renders a template that should not be publicly accessible or discloses sensitive information, then the vulnerability is confirmed.
     - If a 404 error is returned in a manner that does not leak internal path details, further testing with various traversal patterns should be performed to ensure robust sanitization.
  3. Repeat tests with different traversal inputs to confirm that the path traversal issue remains.

---

It is strongly recommended that these vulnerabilities—especially the insecure deserialization, dynamic module import, and template path traversal—be addressed promptly to ensure a secure-by-design posture in publicly accessible deployments.
