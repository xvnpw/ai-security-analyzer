## Consolidated Vulnerability List for django-unicorn

This document combines and consolidates vulnerabilities found in django-unicorn from the provided lists, removing duplicates and presenting them in a structured format.

### 1. Cross-Site Scripting (XSS) vulnerability due to unsafe HTML attributes

- **Vulnerability Name:** Cross-Site Scripting (XSS) vulnerability due to unsafe HTML attributes
- **Description:**
    1. An attacker can craft a malicious string that, when used as an attribute value in a Django template rendered by django-unicorn, will execute arbitrary JavaScript code in the victim's browser.
    2. This is possible because while django-unicorn by default HTML-encodes updated field values to prevent XSS in HTML tag content, this encoding is not consistently applied in all contexts, specifically within HTML attributes.
    3. An attacker can inject malicious JavaScript code through component properties that are used to dynamically generate HTML attributes in Django templates.
    4. When the component updates and the template is re-rendered, if these properties are not properly encoded, the injected JavaScript code will be executed in the user's browser via the HTML attribute.
- **Impact:**
    * Successful exploitation of this vulnerability allows an attacker to execute arbitrary JavaScript code in the context of the victim's browser.
    * This can lead to various malicious actions, including but not limited to:
        * Stealing user session cookies and hijacking user accounts.
        * Performing actions on behalf of the user without their knowledge or consent.
        * Defacing the web page or redirecting the user to malicious websites.
        * Phishing attacks by displaying fake login forms.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    * According to `changelog.md` - "Security fix: for CVE-2021-42053 to prevent XSS attacks". It is mentioned that responses will be HTML encoded going forward and to opt-out, the `safe` filter/attribute should be used.
    * `views.md` mentions "By default, `unicorn` HTML encodes updated field values to prevent XSS attacks. You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple."
    * The file `django_unicorn\utils.py` contains `sanitize_html` function which escapes HTML/XML special characters. However, this function is primarily used for JSON data within `<script>` tags and not consistently applied to HTML attribute values during template rendering.
- **Missing Mitigations:**
    * While django-unicorn includes HTML encoding for updated field values as a default mitigation, this is focused on the content within HTML tags. It does not appear to consistently apply HTML encoding to component properties used to dynamically generate HTML attributes.
    * Mitigation is missing to ensure that HTML encoding is automatically and consistently applied to component properties when they are used to dynamically set HTML attributes in Django templates.
    * There is no explicit documentation or code in the provided files confirming that attribute values are automatically encoded by default to prevent attribute-based XSS.
- **Preconditions:**
    * Application using django-unicorn is deployed and publicly accessible.
    * A component is designed such that its properties can influence HTML attributes in the rendered template.
    * An attacker can control or influence the data that populates these component properties, potentially through URL parameters, form inputs, or other means.
- **Source Code Analysis:**
    1. **`changelog.md` and `views.md`**: Indicate that django-unicorn has implemented HTML encoding as a security measure against XSS for tag content, but these documents do not explicitly mention attribute encoding. The `safe` Meta attribute allows developers to opt-out of encoding for specific fields, implying a default encoding for tag content.
    2. **`django_unicorn\utils.py`**: The `sanitize_html` function is available for HTML escaping, but its usage is limited. It is used in `UnicornTemplateResponse` to sanitize the `init` JSON data that is embedded within a `<script>` tag, as seen in `UnicornTemplateResponse.render` method.
    3. **`django_unicorn\components\unicorn_template_response.py`**: This file handles the rendering of the component template. The `UnicornTemplateResponse.render` method uses BeautifulSoup to parse and manipulate the HTML content. While it adds `unicorn:` attributes to the root element, it does not perform HTML encoding on dynamically generated attributes derived from component properties within the template itself. The `UnsortedAttributes` class is used as a formatter for BeautifulSoup, but it only preserves the order of attributes and does not apply any encoding. The `_desoupify` method simply converts the BeautifulSoup object back to a string without any encoding of attribute values.
    4. **`django_unicorn\templatetags\unicorn.py`**: The `unicorn` template tag is responsible for rendering components within Django templates. `UnicornNode.render` method orchestrates component creation and rendering by calling `UnicornView.create` and `UnicornView.render`. This process does not include explicit HTML attribute encoding for component properties being inserted into attributes within the template.
    5. **`django_unicorn\views\__init__.py`**: The `_process_component_request` function renders the component using `component.render(request=request)`. Before rendering, it checks for `safe_fields` defined in the component's Meta class and marks these fields as safe using `mark_safe`. This safety mechanism applies to the content within HTML tags, not to HTML attribute values. The function does not include any attribute encoding logic.
    **Visualization**:
    ```
    [Django Template] --> {% unicorn component_name dynamic_attribute=component.property %} --> [Unicorn Template Tag] --> UnicornNode.render() --> UnicornView.create() --> UnicornView.render() --> UnicornTemplateResponse.render() --> BeautifulSoup parsing --> Attribute values from component.property inserted into HTML attributes (no encoding) --> _desoupify() --> [HTML Response]
    ```

    **Conclusion**: The source code analysis consistently points to a lack of automatic HTML encoding for component properties when used in HTML attributes.  The existing vulnerability related to XSS in HTML attributes remains unmitigated based on the analyzed code.
- **Security Test Case:**
    1. Create a django-unicorn component named `attribute_xss` in your Django application.
    2. In `attribute_xss.py`, define a component view `AttributeXSSView` with a property `dynamic_attribute` initialized with a safe string, e.g., `dynamic_attribute = "safe_value"`.
    3. In `attribute_xss.html`, use this property to dynamically set an HTML attribute, for example:
        ```html
        <div id="vuln-div" data-attribute="{{ dynamic_attribute }}">
            Safe content here.
        </div>
        ```
    4. Create a Django view and template to include the `attribute_xss` component.
    5. Access the page in a browser and inspect the HTML source of `vuln-div`. Confirm that `data-attribute` is `safe_value`.
    6. Now, modify the `AttributeXSSView` to set `dynamic_attribute` to a malicious string containing JavaScript, such as: `dynamic_attribute = "><img src=x onerror=alert('XSS')>"`. You can simulate this data coming from an external source or directly modify the component property in the view for testing purposes.
    7. Refresh the page in the browser.
    8. **Expected Result (Vulnerability Present):** An alert box with 'XSS' should appear, indicating that the JavaScript code in `dynamic_attribute` was executed. Inspect the HTML source again; you should see the injected JavaScript within the `data-attribute`. For example, you might see `<div id="vuln-div" data-attribute="><img src=x onerror=alert('XSS')>">`.
    9. **Expected Result (Mitigation Present):** No alert box should appear. Inspect the HTML source and verify that the malicious string in `data-attribute` is HTML-encoded, preventing JavaScript execution. For example, `<div id="vuln-div" data-attribute="&gt;&lt;img src=x onerror=alert(&#x27;XSS&#x27;)&gt;">`.

### 2. Cross-Site Scripting (XSS) due to Inadequate HTML Sanitization

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

- **Security Test Case:**
    1. **Setup:**
        - Create a Django Unicorn component that renders a property which can be influenced by user input (e.g., from a form field or URL parameter).
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
        2. **Craft XSS Payload:** `<img src="x" onerror="alert('XSS')">`
        3. **Inject Payload:** Via URL parameter e.g., `/?message=<img src="x" onerror="alert('XSS')">` and pass message as kwargs to component.
        4. **Trigger Rendering:** Access the page in a browser.
        5. **Verify XSS:** Check if JavaScript code (`alert('XSS')`) executes.
        6. **Alternative Payloads:** Test with payloads like `<svg><script>alert('XSS')</script></svg>`, `<body onload="alert('XSS')">`, `<iframe src="javascript:alert('XSS')">`, `<div onmouseover="alert('XSS')">Hover Me</div>`.

### 3. Unsafe Deserialization via Pickle in Component Caching and SSRF/RCE

- **Vulnerability Name:** Unsafe Deserialization via Pickle in Component Caching and Server-Side Request Forgery (SSRF)/Remote Code Execution (RCE)
- **Description:**
    - Django-unicorn uses `pickle` for caching component state in `django_unicorn\cacher.py`. The `cache_full_tree` function serializes the component and its children using `pickle.dumps`, and `restore_from_cache` deserializes it using `pickle.loads`.
    - Pickle is known to be insecure when used to deserialize data from untrusted sources. A malicious attacker could craft a pickled payload that, when deserialized by the server, executes arbitrary code on the server or performs Server-Side Request Forgery.
    - An attacker could potentially exploit this if they can control or influence the cached data, such as by manipulating the component's cache key or by injecting malicious data into the cache backend if the cache is shared or exposed.
- **Impact:**
    - **Critical**
    - Remote Code Execution (RCE) and Server-Side Request Forgery (SSRF). An attacker can execute arbitrary Python code on the server hosting the Django application, or make requests to internal or external resources from the server. This can lead to full server compromise, data breach, and other severe security incidents.
- **Vulnerability Rank:** critical
- **Currently Implemented Mitigations:**
    - None. The project uses `pickle` for serialization and deserialization without any apparent sanitization or security measures. Documentation does not warn against pickle risks.
- **Missing Mitigations:**
    - **Use of Safe Serialization Format:** Replace `pickle` with a safer serialization format like `orjson` or `jsonpickle`.  `orjson` is already a dependency.
    - **Security Warning in Documentation:** Add a prominent security warning in the documentation about the risks of using pickle for caching, recommend safer alternatives.
- **Preconditions:**
    - Caching must be enabled in django-unicorn settings (`UNICORN['SERIAL']['ENABLED'] = True`).
    - A cache backend that persists data between requests must be in use (e.g., Redis, Memcached, Database cache).
    - An attacker needs to find a way to influence or control the data stored in the cache.
- **Source Code Analysis:**
    - File: `django_unicorn\cacher.py`
    ```python
    def cache_full_tree(component: "django_unicorn.views.UnicornView"):
        ...
        cache = caches[get_cache_alias()]
        with CacheableComponent(root) as caching:
            for _component in caching.components():
                cache.set(_component.component_cache_key, _component) # Serialization using pickle.dumps
    def restore_from_cache(
            component_cache_key: str,
            request: Optional[HttpRequest] = None
        ) -> "django_unicorn.views.UnicornView":
        ...
        cache = caches[get_cache_alias()]
        cached_component = cache.get(component_cache_key) # Deserialization using pickle.loads
        ...
        return cached_component
    ```
    - `cache.set` and `cache.get` use `pickle` for serialization by default in Django cache backends when storing Python objects.
    - No sanitization is performed before caching or after retrieval.
- **Security Test Case:**
    1. **Setup:** Enable caching (`UNICORN['SERIAL']['ENABLED'] = True`), use persistent cache backend.
    2. **Craft Malicious Payload (SSRF Example):**
        ```python
        import pickle, base64, urllib.request
        class SSRFPayload(object):
            def __reduce__(self):
                url = "http://localhost:8080"
                return (urllib.request.urlopen, (url,))
        pickled_payload = base64.b64encode(pickle.dumps(SSRFPayload())).decode()
        print(pickled_payload)
        ```
    3. **Inject Payload into Cache:** Manually inject `pickled_payload` into cache with a known component cache key.
    4. **Trigger Component Restoration:** Make request to application that triggers `restore_from_cache`.
    5. **Verify SSRF/RCE:** Monitor network traffic/logs for SSRF or RCE side effects.

### 4. Unsafe Deserialization via Pickle in Component Resetting

- **Vulnerability Name:** Unsafe Deserialization via Pickle in Component Resetting
- **Description:**
    - Django-unicorn uses `pickle` for serializing and deserializing component attribute values in `django_unicorn\components\unicorn_view.py` `reset` method.
    - The `_set_resettable_attributes_cache` function serializes attributes of type `UnicornField` and Django Models without PK using `pickle.dumps`.
    - The `reset` function deserializes these pickled values using `pickle.loads` when the component's `reset()` method is called, e.g., via `$reset` action.
    - Pickle is insecure and could lead to Remote Code Execution if attacker controls pickled data.
- **Impact:**
    - **High** (potentially Critical)
    - Remote Code Execution (RCE). If attacker can control pickled data in `_resettable_attributes_cache` and trigger reset, arbitrary Python code can be executed.
- **Vulnerability Rank:** high
- **Currently Implemented Mitigations:**
    - None. Pickle is used without sanitization.
- **Missing Mitigations:**
    - Replace `pickle` with safer serialization format like `json` or `orjson`.
    - Implement integrity checks if pickle is essential (but safer format is recommended).
- **Preconditions:**
    - Component must have resettable attributes (`UnicornField` or Django `Model` without PK).
    - Attacker needs to influence pickled data in `_resettable_attributes_cache` (attack vector needs further investigation).
    - Attacker must trigger component reset (e.g., `$reset` action).
- **Source Code Analysis:**
    - File: `django_unicorn\components\unicorn_view.py`
    ```python
    class UnicornView(TemplateView):
        ...
        def _set_resettable_attributes_cache(self) -> None:
            ...
            for attribute_name, attribute_value in self._attributes().items():
                if isinstance(attribute_value, UnicornField):
                    self._resettable_attributes_cache[attribute_name] = pickle.dumps(attribute_value) # Serialization
                elif isinstance(attribute_value, Model) and not attribute_value.pk:
                    self._resettable_attributes_cache[attribute_name] = pickle.dumps(attribute_value) # Serialization
        def reset(self):
            for (
                attribute_name,
                pickled_value,
            ) in self._resettable_attributes_cache.items():
                try:
                    attribute_value = pickle.loads(pickled_value)  # Deserialization
                    self._set_property(attribute_name, attribute_value)
                except pickle.PickleError:
                    logger.warn(...)
    ```
    - `_set_resettable_attributes_cache` uses `pickle.dumps` to serialize attributes.
    - `reset` uses `pickle.loads` to deserialize, vulnerable if pickled data is controlled.
- **Security Test Case:**
    1. Create component with `UnicornField` attribute.
    2. Craft malicious pickle payload.
    3. **(Theoretical step):** Find/simulate way to inject/replace pickled value for `my_field` in `_resettable_attributes_cache`.
    4. Replace pickled value in `_resettable_attributes_cache` with malicious payload.
    5. Trigger `call_reset` action to call `self.reset()`.
    6. Verify code execution.

### 5. Unsafe arbitrary Python code execution via `call_method_parser.py`

- **Vulnerability Name:** Unsafe arbitrary Python code execution via `call_method_parser.py`
- **Description:**
    - The `django_unicorn/call_method_parser.py` file parses method calls from frontend strings using `ast.parse` and `ast.literal_eval`.
    - A malicious method call string could be crafted to execute arbitrary Python code when parsed.
    - Trigger: Attacker crafts request to `/unicorn/message` endpoint, injects malicious method name in `actionQueue` payload for `callMethod` action.
    - Backend server parses with `parse_call_method_name` using unsafe `ast.parse`.
- **Impact:**
    - **Critical** - Remote Code Execution (RCE). Attacker can execute arbitrary Python code, leading to server compromise.
- **Vulnerability Rank:** critical
- **Currently Implemented Mitigations:**
    - None. Direct use of `ast.parse` on user input.
- **Missing Mitigations:**
    - **Input sanitization and validation:** Whitelist allowed methods and argument types. Do not parse arbitrary strings as code.
    - **Secure parsing:** Replace `ast.parse` with safer parsing (regex, dedicated parsing library).
    - **Principle of least privilege:** Minimize permissions of web server process.
- **Preconditions:**
    - Publicly accessible django-unicorn application.
    - Actions can be triggered by external users.
- **Source Code Analysis:**
    - File: `django_unicorn/call_method_parser.py`
    - Function: `parse_call_method_name`
    ```python
    def parse_call_method_name(
        call_method_name: str,
    ) -> Tuple[str, Tuple[Any, ...], Mapping[str, Any]]:
        ...
        tree = ast.parse(method_name, "eval") # [!] Unsafe ast.parse
        ...
    ```
    - `ast.parse(method_name, "eval")` compiles user-controlled `method_name` string into AST, allowing code injection.
- **Security Test Case:**
    1. Endpoint: `/unicorn/message`.
    2. Craft JSON POST request:
        ```json
        {
          "id": "testComponentId", "name": "testComponentName", "epoch": 1678886400, "checksum": "valid_checksum",
          "actionQueue": [{
            "type": "callMethod",
            "payload": {
              "name": "__import__('os').system('touch /tmp/unicorn_pwned')",
              "args": [], "kwargs": {}
            },
            "partials": []
          }], "data": {}
        }
        ```
    3. Replace placeholders, generate valid checksum.
    4. Send request.
    5. Verify command injection (check for `/tmp/unicorn_pwned`).
