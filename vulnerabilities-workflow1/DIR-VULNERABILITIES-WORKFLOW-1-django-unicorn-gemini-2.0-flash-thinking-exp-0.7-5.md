### Vulnerability List:

- **Vulnerability Name:** Server-Side Template Injection (Potential)
- **Description:**
    - The django-unicorn library allows dynamic component rendering and method calls from the frontend.
    - Attackers could potentially craft malicious input within component templates or method arguments if user-controlled data is directly embedded without proper sanitization into template rendering or action method arguments.
    - While Django templates offer built-in protections, developers might inadvertently introduce template injection vulnerabilities when using custom template tags/filters or bypassing autoescaping in dynamic template generation scenarios.
    - For example, if a component dynamically renders a template snippet based on user input without sanitization, malicious template code injection is possible.
- **Impact:**
    - High: Successful template injection can lead to arbitrary code execution on the server, data exfiltration, or complete application compromise. This is a severe vulnerability allowing full control over the backend.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - Django's template engine with default autoescaping to prevent basic XSS.
    - Documentation mentions security considerations and CSRF tokens, indicating general security awareness.
    - Version 0.36.0 includes a security fix for CVE-2021-42053 (XSS), showing past efforts to address output encoding issues.
- **Missing Mitigations:**
    - No explicit input sanitization guidance in django-unicorn documentation for dynamic template rendering or method arguments handling user-provided data, increasing the risk of developer error.
    - Lack of clear security guidelines on preventing template injection when composing dynamic templates or handling external input within component logic, leaving room for insecure implementations.
    - Absence of automated security tests specifically targeting Server-Side Template Injection vulnerabilities, meaning this class of vulnerability might not be regularly checked.
- **Preconditions:**
    - Application uses django-unicorn components.
    - Developer implements dynamic template rendering or processes user-controlled input within components or templates without proper sanitization.
    - User-controlled data is directly embedded into template context or action method arguments without sufficient output encoding or input validation, a common mistake if security best practices are not followed.
- **Source Code Analysis:**
    - `django_unicorn/utils.py`'s `create_template` function uses Django's template engine to render templates from strings. If a component uses this with unsanitized user input in `template_html`, SSTI can occur.
    - `django_unicorn/components/unicorn_view.py`'s `_set_default_template_name` method uses `create_template` if `template_html` is set, highlighting a potential path for SSTI if developers use this dynamically with user input.
    - `django_unicorn/templatetags/unicorn.py` focuses on component rendering and doesn't directly use `create_template` with user input. The risk is primarily from developer misuse of `create_template` within components.
    - Further review of component examples and tests is needed to assess if dynamic template generation from user input is a common or discouraged pattern. Current analysis suggests the library itself isn't directly vulnerable, but developer misuse is a significant concern.
- **Security Test Case:**
    1. Create a django-unicorn component with a dynamically constructed `template_html` attribute based on user input via `unicorn:model`.
    2. Use a template variable in `template_html` to render the user-controlled property.
    3. Render the component in a template.
    4. Craft a malicious input string with template code (e.g., `{{request.environ.SECRET_KEY}}` for information disclosure or more severe payloads for RCE).
    5. Input the malicious string via `unicorn:model` bound to the component property used in `template_html`.
    6. Examine the server response and rendered page for malicious template code execution or sensitive information leaks.
    7. Verify if Django's autoescaping effectively prevents the injection or if it's bypassed in this dynamic rendering scenario.
    8. Successful exploitation confirms a potential Server-Side Template Injection vulnerability due to dynamic template generation with unsanitized user input.

- **Vulnerability Name:** Cross-Site Scripting (XSS) via Unsafe HTML Output
- **Description:**
    - While django-unicorn aims to prevent XSS with Django's autoescaping, developers can bypass this using the `safe` filter in templates or the `safe` Meta option in components.
    - If a component's Python code prepares HTML content and marks it as safe (via `mark_safe` or `safe_fields` in Meta), and this content is based on unsanitized user input or untrusted sources, XSS vulnerabilities can arise.
    - `views/__init__.py` shows `Meta.safe` attributes are marked as safe using `mark_safe` before rendering. Unsanitized user input in these attributes leads to XSS.
- **Impact:**
    - High: Successful XSS allows attackers to execute arbitrary JavaScript code in users' browsers. This can lead to session hijacking, cookie theft, website defacement, or redirects to malicious sites, significantly impacting user security and trust.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - Django's template engine's default autoescaping is a baseline protection against XSS.
    - Security fix in v0.36.0 (CVE-2021-42053) implemented HTML encoding by default, demonstrating a focus on preventing XSS.
    - Documentation mentions HTML encoding and the `safe` option as a deliberate bypass, putting control in developers' hands.
- **Missing Mitigations:**
    - Lack of prominent documentation warnings against using `Meta.safe` or the `safe` filter with user-provided/untrusted HTML without thorough sanitization. This increases the risk of developers unknowingly introducing XSS.
    - No built-in mechanisms in django-unicorn to automatically sanitize HTML content before marking it as safe or rendering it as safe when `Meta.safe` is used. Developers are solely responsible for sanitization.
    - Security tests might not comprehensively cover all misuse scenarios of the `safe` feature and potential XSS, especially concerning `Meta.safe`, potentially missing vulnerabilities in real-world usage.
- **Preconditions:**
    - Application uses django-unicorn components.
    - Developer uses the `safe` Meta option in a component to render HTML content, intending to allow HTML rendering.
    - The HTML content marked as safe originates from an untrusted source or is not properly sanitized before being marked as safe, indicating a security oversight in handling user input.
- **Source Code Analysis:**
    - `django_unicorn/views/__init__.py`'s `_process_component_request` function iterates through `safe_fields` from `component.Meta.safe`. It retrieves attribute values and uses `mark_safe(value)` if the value is a string, bypassing autoescaping.
    - ```python
      # Get set of attributes that should be marked as `safe`
      safe_fields = []
      if hasattr(component, "Meta") and hasattr(component.Meta, "safe"):
          if isinstance(component.Meta.safe, Sequence):
              for field_name in component.Meta.safe:
                  if field_name in component._attributes().keys():
                      safe_fields.append(field_name)

      # Mark safe attributes as such before rendering
      for field_name in safe_fields:
          value = getattr(component, field_name)
          if isinstance(value, str):
              setattr(component, field_name, mark_safe(value))  # noqa: S308
      ```
    - If a developer includes a component property in `Meta.safe` and sets its value directly from user input without sanitization, `mark_safe` will bypass Django's autoescaping, leading to XSS when the template renders this property. This is a direct path to XSS if `Meta.safe` is misused.
    - `django_unicorn/utils.py`'s `sanitize_html` function exists but is not used before `mark_safe` in `views/__init__.py`.  `sanitize_html` is for JSON escaping, not general HTML sanitization, so it doesn't mitigate this XSS risk.
- **Security Test Case:**
    1. Create a django-unicorn component.
    2. Define a `Meta` class with `safe = ("unsafe_html",)` to explicitly mark `unsafe_html` as safe for HTML rendering.
    3. Define an `unsafe_html` property in the component to hold potentially unsafe HTML.
    4. Render the `unsafe_html` property in the component's template.
    5. Create a component method to set `self.unsafe_html` to user-controlled input (e.g., from `unicorn:model` or method arguments), simulating a scenario where user input is dynamically rendered as "safe" HTML.
    6. Craft a malicious input string containing a JavaScript payload (e.g., `<img src=x onerror=alert('XSS')>`) to test for XSS.
    7. Trigger the component method to set `self.unsafe_html` with the malicious payload.
    8. Render the component on a page.
    9. Observe if the JavaScript payload executes in the browser when the page loads, indicating successful XSS.
    10. If JavaScript code executes (e.g., an alert box appears), this confirms an XSS vulnerability due to the unsafe use of `Meta.safe` with unsanitized user input.

- **Vulnerability Name:** Insecure Deserialization (Potential - if Serialized Requests Feature is Enabled)
- **Description:**
    - django-unicorn's experimental "Queue Requests" feature, enabled via `SERIAL.ENABLED = True`, may involve serialization/deserialization of component state for handling slow requests.
    - Insecure deserialization in component state handling could allow attackers to craft malicious serialized data. When deserialized by the server, this could lead to remote code execution or other critical security breaches.
    - `cacher.py` (from prior analysis) uses `pickle` for serialization/deserialization. `pickle` is known to be vulnerable to insecure deserialization, especially with untrusted data.
    - If serialized component state is exposed or manipulable, this could become a critical vulnerability, allowing complete server takeover.
- **Impact:**
    - Critical: Insecure deserialization can lead to remote code execution. This is the highest severity, as it allows attackers to gain complete control of the server and application, potentially leading to data breaches, service disruption, and further malicious activities.
- **Vulnerability Rank:** Critical (if exploitable)
- **Currently Implemented Mitigations:**
    - The "Queue Requests" feature is experimental and disabled by default, limiting the immediate attack surface.
    - Documentation warns against using this feature with dummy cache backends, suggesting it's intended for controlled environments and implying caution is needed.
    - `cacher.py` uses standard `pickle.dumps` and `pickle.loads`, but lacks explicit custom sanitization or validation, relying solely on the inherent security of `pickle` (which is known to be insufficient against malicious payloads).
- **Missing Mitigations:**
    - No input validation or sanitization of serialized data before deserialization in `cacher.py`, leaving the system vulnerable to malicious pickle payloads.
    - No use of safer serialization methods than `pickle` (e.g., `json`, `marshal`, or cryptographic signing of serialized data) which would reduce or eliminate the risk of RCE via deserialization.
    - Lack of clear security warnings in documentation about the risks of enabling "Queue Requests", especially in production, regarding insecure deserialization. Developers might enable this feature without understanding the serious security implications.
    - No security tests specifically targeting insecure deserialization vulnerabilities in the "Queue Requests" feature, meaning this critical vulnerability is not actively checked in development.
- **Preconditions:**
    - The "Queue Requests" feature (`SERIAL.ENABLED = True`) is enabled in django-unicorn settings, explicitly opting into this experimental and potentially risky feature.
    - An attacker can influence or provide malicious serialized data that the application deserializes. The exact attack vector for injecting malicious pickle data needs further investigation, but could involve cache poisoning or other vulnerabilities.
- **Source Code Analysis:**
    - `django_unicorn/components/unicorn_view.py`'s `_cache_component` and `create` methods interact with caching, calling `cache_full_tree` and `restore_from_cache` respectively, indicating where caching and deserialization occur.
    - `django_unicorn/cacher.py`'s `cache_full_tree`, `restore_from_cache`, and `CacheableComponent` use `pickle.dumps` and `pickle.loads` for serialization and deserialization of component state, confirming the use of potentially insecure `pickle`.
    - If an attacker can control cached data (e.g., by compromising the cache backend or via a vulnerability allowing cache writes), they could inject a malicious pickled payload. `restore_from_cache` then deserializes this payload with `pickle.loads`, potentially leading to RCE.
    - Example project `settings.py` sets `SERIAL.ENABLED = True` and `CACHE_ALIAS = 'default'` using `django.core.cache.backends.locmem.LocMemCache`. While `LocMemCache` is in-memory, production might use shared caches like Redis or Memcached, which could be targeted if not secured, making cache injection a more realistic attack vector in deployed environments.
- **Security Test Case:**
    1. Enable "Queue Requests" in `settings.py` (`UNICORN = {'SERIAL': {'ENABLED': True}}`) to activate the vulnerable feature.
    2. Configure django-unicorn to use a shared cache backend like Redis for a more realistic test environment (though `LocMemCache` can be used for initial local testing). Using a shared cache increases the potential attack surface in a real deployment.
    3. Craft a malicious Python pickle payload that executes arbitrary code upon deserialization (e.g., using `pickle.loads` with a payload importing `os` and running a system command). Tools like `pickletools` or `ysoserial` can assist in creating these payloads.
    4. **Crucially, identify an attack vector to inject the malicious pickle payload into the cache.** This is the most challenging step. Investigate potential cache poisoning vulnerabilities or other means to write arbitrary data to the cache with a known key. If direct cache manipulation is not feasible in a real-world scenario within the library's context, simulate it for testing by directly modifying the cache backend. This is necessary to test the deserialization vulnerability.
    5. Trigger a request that leads to retrieval and deserialization of the cached component state using `restore_from_cache`. This typically occurs when a component is re-rendered after a request queue is processed, which is part of the "Queue Requests" feature's functionality.
    6. Monitor server-side behavior for code execution (e.g., check logs, file system changes, network activity) to confirm if the injected code ran.
    7. Successful code execution confirms a critical Insecure Deserialization vulnerability in the "Queue Requests" feature, demonstrating the severe risk if this experimental feature is enabled and exploitable.

- **Vulnerability Name:** Insecure Argument Parsing in Method Calls (Potential)
- **Description:**
    - django-unicorn uses a parser to process arguments passed to component methods from the frontend.
    - If the argument parsing mechanism, specifically `eval_value` in `django_unicorn.call_method_parser`, uses unsafe functions like `eval()` or `exec()` without proper sanitization/validation, it could lead to arbitrary code execution.
    - Attackers might inject malicious payloads within arguments of method calls triggered from the frontend (e.g., via `unicorn:click`, `unicorn:model`). This allows for direct interaction with backend logic through frontend requests.
- **Impact:**
    - Critical: Successful exploitation can lead to remote code execution on the server. This is a critical impact, allowing attackers to take complete control of the application and server by sending malicious requests from the frontend.
- **Vulnerability Rank:** Critical (if exploitable)
- **Currently Implemented Mitigations:**
    - Django's template engine autoescaping protects against basic XSS in template rendering output but does not mitigate server-side code execution risks from insecure argument parsing.
    - General security awareness is implied by documentation mentions of CSRF tokens and past XSS fixes, but this doesn't specifically address insecure argument parsing.
- **Missing Mitigations:**
    - No input sanitization or validation of arguments passed to component methods. The library appears to rely on potentially unsafe parsing without any explicit security checks on the input data.
    - Use of a secure parsing mechanism for arguments, avoiding unsafe functions like `eval()` or `exec()`. A safer parsing approach is essential to prevent code injection through method arguments.
    - No security tests specifically targeting insecure argument parsing vulnerabilities in method calls. This critical area is not actively tested, increasing the risk of this vulnerability existing in the library.
- **Preconditions:**
    - Application uses `django-unicorn` components, making it potentially vulnerable to this library-specific issue.
    - Component methods are called from the frontend with arguments, utilizing the method call feature that is potentially vulnerable.
    - Argument parsing in `django_unicorn.call_method_parser.eval_value` is vulnerable to code injection, meaning the parsing logic itself is flawed and allows for execution of attacker-controlled code.
- **Source Code Analysis:**
    - Source code analysis of `django_unicorn.call_method_parser.eval_value` is crucial to confirm if it uses unsafe parsing functions like `eval()` or `exec()`. (Source code not directly provided, requiring code review of the library).
    - If `eval_value` uses `eval()` or similar functions directly on frontend-provided strings to parse arguments, it's highly likely to be vulnerable to remote code execution. This function is the key point of investigation.
- **Security Test Case:**
    1. Create a django-unicorn component with a method that accepts an argument, representing a typical component interaction.
    2. In the component's template, create a button or input field to trigger this method call with a user-controlled argument (e.g., using `unicorn:click` with an argument from `unicorn:model`). This simulates a user interacting with the vulnerable component.
    3. Craft a malicious payload as an argument to attempt code execution when parsed by `eval_value` (e.g., `'__import__("os").system("whoami")'` as a string argument). The payload needs to be a valid argument string that, when parsed unsafely, results in code execution. Encoding or escaping might be needed depending on expected argument format.
    4. Trigger the method call from the frontend with the malicious payload as the argument. This simulates an attacker sending a malicious request.
    5. Monitor server-side logs or system behavior to detect code execution (e.g., check for output of `whoami` command or other signs of injected code running).
    6. Successful code execution confirms an Insecure Argument Parsing vulnerability, demonstrating the critical risk of this parsing mechanism.
