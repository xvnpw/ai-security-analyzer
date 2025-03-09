## Vulnerability List for django-unicorn Project

### 1. Potential Remote Code Execution via Deserialization of Arbitrary Objects in Component State

- Description:
    1. An attacker can manipulate the component's serialized state, potentially injecting malicious serialized Python objects.
    2. When the server attempts to deserialize this manipulated state, it could lead to the execution of arbitrary code on the server.
    3. This is possible if the deserialization process within django-unicorn doesn't properly validate or sanitize the incoming serialized data, and if the application uses cache in a way that an attacker can influence the cached data.
    4. The vulnerability is related to the caching mechanism and how component state is serialized and deserialized, particularly when handling dataclasses, Pydantic models, and Django Models during type casting and model construction. The `_construct_model` function used for Django Model construction from client-provided data is a potential point of concern.

- Impact:
    - Critical: Successful exploitation can lead to complete server takeover, allowing the attacker to execute arbitrary commands, access sensitive data, and potentially compromise the entire application and underlying infrastructure.

- Vulnerability Rank: critical

- Currently implemented mitigations:
    - The project uses `orjson` for serialization which is generally considered safer than `pickle` for untrusted data.
    - Checksum is used to verify integrity of component state. The checksum is generated in `django_unicorn.utils.generate_checksum` and validated in `django_unicorn.views.objects.ComponentRequest.validate_checksum`. The checksum is calculated over the component's data.

- Missing mitigations:
    - Input validation and sanitization of serialized data before deserialization to prevent deserialization of unexpected or malicious objects. While `orjson` is used, it doesn't inherently prevent deserialization vulnerabilities if the application logic allows for arbitrary data structures to be serialized and then deserialized without proper type checking and validation after deserialization.
    - Cryptographic signing of the serialized state to ensure integrity and prevent tampering. While a checksum is in place, it might not be cryptographically signed, and the scope of what is covered by the checksum needs to be carefully reviewed to ensure it covers all critical parts of the serialized state that could be manipulated to achieve RCE.
    - Robust checks to ensure only expected data types are deserialized and instantiated, preventing arbitrary object instantiation even if `orjson` is used. The `django_unicorn.typer.cast_value` function shows logic for casting values based on type hints, including handling of Pydantic models, dataclasses and Django Models. If vulnerabilities exist in how these objects are constructed from deserialized data, RCE could be possible. Specifically, the use of `_type_hint(**value)` in `cast_value` for dataclasses and Pydantic models, and the use of `_construct_model(_type_hint, value)` for Django Models are potential vulnerability points if the `value` is attacker-controlled and not properly validated.

- Preconditions:
    - Caching must be enabled and used for component state persistence, or the attacker can manipulate the request data directly.
    - An attacker needs to be able to intercept or influence the cached component state, or manipulate the state during transit to the server or directly in the request. This could potentially involve cache poisoning if the application's caching mechanism is vulnerable, or manipulation of network traffic if communication between client and server is not properly secured, or direct manipulation of AJAX request parameters.
    - The application must be deployed in a publicly accessible environment.

- Source code analysis:
    1. **File: django_unicorn\cacher.py**: This file is responsible for caching and restoring component state. It's crucial to verify how the cache is used and if there are any weaknesses in the caching mechanism that could allow an attacker to inject malicious serialized data. The code utilizes Django's caching framework.
    2. **File: django_unicorn\serializer.py**: The `dumps` and `loads` functions use `orjson`.  The `_json_serializer` function is responsible for handling different object types during serialization and deserialization. It supports Django Models, QuerySets, Pydantic models, and custom objects with `to_json` methods. If an attacker can control the data within these objects, especially through manipulation of type hints or by providing crafted JSON payloads, and if the deserialization process in `_json_serializer` doesn't strictly enforce expected types and structures after deserialization by `orjson`, RCE might be possible. Review the logic in `_json_serializer` for vulnerabilities.
    3. **File: django_unicorn\typer.py**:
        - The `cast_value` function attempts to cast values based on type hints. This function handles various types including `datetime`, `date`, `timedelta`, `UUID`, `bool`, Django Models, Pydantic models, and dataclasses.
        - For dataclasses and Pydantic models: `elif is_dataclass(_type_hint) or is_pydantic_base(_type_hint): if value is not None: return _type_hint(**value)`. This uses direct instantiation with `**value`, which can be dangerous if `value` is attacker-controlled and contains malicious data that can exploit constructor logic.
        - For Django Models: `elif isinstance(_type_hint, ModelBase): return _construct_model(_type_hint, value)`. It calls `_construct_model`.
        - **File: django_unicorn\typer.py**: The `_construct_model` function is used to construct Django Model instances from data. It is called from `cast_value` when handling Django Model type hints.
        - **File: django_unicorn\tests\views\utils\test_construct_model.py**: Tests for `_construct_model` show it takes a model class and data dictionary, and constructs a model instance. It uses `**model_data` to pass data to the model's constructor or field assignments. If `model_data` is attacker-controlled and contains malicious payloads, it could lead to RCE during model construction.
    4. **File: django_unicorn\views\objects.py**: `ComponentRequest.validate_checksum` validates the checksum of the data. However, if the data itself is crafted to be malicious, and the checksum only verifies integrity but not the safety of the data itself, then the checksum might not prevent RCE.  The checksum mechanism needs to be reviewed to ensure it protects against RCE scenarios.
    5. **File: django_unicorn\views\utils\set_property_from_data.py**: This function is used to set component properties from data, and it utilizes `cast_value` to handle type casting, including for Django Models, Pydantic models and dataclasses.  If the input data is not validated before being passed to `cast_value` and subsequently to `_construct_model` or object constructors via `**value`, it can lead to RCE.
    6. **Visualization**: Data flow: User interaction -> Client-side serialization -> Server-side deserialization via cache (or directly in request) -> `_json_serializer` and `cast_value` -> `_construct_model` (for Django Models) or direct instantiation with `**value` (for dataclasses/Pydantic models) -> Component state update. Vulnerability could be in the deserialization and object construction step if attacker can control the serialized data and exploit weaknesses in `_json_serializer`, `cast_value`, or `_construct_model`, especially in how Django Models, Pydantic models, and dataclasses are handled via `_construct_model(_type_hint, value)` and `_type_hint(**value)`.

- Security test case:
    1. **Setup**: Deploy a django-unicorn application with caching enabled or target direct request manipulation. Create a component that utilizes caching to persist state and includes a Pydantic model, dataclass, or Django Model in its state. Ensure that the state including these objects can be influenced by client-side data, for example via `unicorn:model` binding.
    2. **Identify Deserialization and Object Construction Point**: Pinpoint the exact code path where component state is deserialized from the cache or request data, focusing on `django_unicorn.serializer.loads`, `django_unicorn.serializer._json_serializer`, `django_unicorn.typer.cast_value`, and `django_unicorn.typer._construct_model`. Specifically target the handling of Pydantic models, dataclasses and Django Models and the use of `_type_hint(**value)` and `_construct_model(_type_hint, value)`.
    3. **Craft Malicious Payload**: Construct a malicious JSON payload that, when deserialized and processed by `orjson`, `_json_serializer`, `cast_value`, and `_construct_model` (or object constructors via `**value`), leads to the instantiation of a malicious Python object or manipulation of model/dataclass/Pydantic model construction in a way that executes arbitrary commands.
        - For Django Models, try to inject malicious data that exploits model's `__init__`, `save` or field setters.
        - For Pydantic models and dataclasses, investigate constructor arguments and properties. Explore if it's possible to inject code through constructor arguments or object properties during deserialization via `_type_hint(**value)`. Look for classes in the application or standard library that, when instantiated with specific parameters, can lead to code execution (e.g., using file paths, commands, etc.).
        - Example payload structure (conceptual, needs to be adapted to specific model/dataclass/Pydantic model and vulnerability): `{"property_name": {"__class__": "...", "__module__": "...", ...malicious_constructor_args...}}`. You might need to bypass or work around `orjson` limitations and checksum. Focus on manipulating data that will be processed by `cast_value` and `_construct_model` after deserialization.
    4. **Manipulate Cached State or Request**: If targeting the cache, attempt to poison the cache with the malicious payload. If targeting the request, intercept and modify the AJAX request to include the crafted malicious JSON payload in the component data.
    5. **Trigger Deserialization/Object Construction**: Trigger an action that causes the server to deserialize the component state and construct the objects, either by accessing the component after cache poisoning, or by sending the manipulated AJAX request. This might involve a user interaction that updates the component state or simply loading the page with the component.
    6. **Verify RCE**: Monitor server logs or system behavior to confirm if the malicious code was executed. Attempt to execute commands that would leave observable traces (e.g., creating a file, network connections, DNS lookups, etc.).
    7. **Expected Result**: If vulnerable, the malicious code will execute on the server, demonstrating RCE. If mitigated, the server should handle the malicious payload safely, without executing the malicious code. Verify that checksum validation is in place and if it can be bypassed or if it's insufficient to prevent RCE in this scenario. Pay attention to how Django Model construction via `_construct_model` and dataclass/Pydantic model construction via `_type_hint(**value)` are handled with malicious input.

### 2. Potential Cross-Site Scripting (XSS) Vulnerability due to Inadequate Output Encoding

- Description:
    1. If the project doesn't properly HTML-encode user-provided data that is dynamically rendered in templates, an attacker could inject malicious JavaScript code.
    2. When a user views a page containing a component with this vulnerability, the injected script can execute in their browser, potentially leading to session hijacking, data theft, or other malicious actions.
    3. The vulnerability is in the template rendering and how user inputs are handled before being displayed.

- Impact:
    - High: Successful XSS attacks can compromise user accounts, steal sensitive information, and deface websites.

- Vulnerability Rank: high

- Currently implemented mitigations:
    - Changelog v0.36.0 mentions a security fix for CVE-2021-42053 to prevent XSS attacks, stating responses will be HTML encoded going forward.
    - `safe` template filter and `Meta.safe` option are provided to opt-in to unencoded output, allowing developers to explicitly mark output as safe when needed.
    - The `sanitize_html` function in `django_unicorn.utils.py` is used, but it is specifically for escaping HTML/XML special characters for JSON output using `_json_script_escapes` from Django, not for general HTML encoding in templates to prevent XSS.

- Missing mitigations:
    - Consistent and comprehensive HTML encoding for all user-provided data rendered in templates by default, unless explicitly marked as safe using `safe` filter or `Meta.safe`. Review if default Django template auto-escaping is consistently applied in django-unicorn's rendering process, especially within component templates and template tags.
    - Thorough review of all instances where `safe` filter or `Meta.safe` is used. Verify if each usage is genuinely necessary and safe, and if there are any instances where it's used incorrectly, potentially re-introducing XSS vulnerabilities.
    - Implementation of Content Security Policy (CSP) headers to provide an additional layer of defense against XSS attacks. CSP can significantly reduce the impact of XSS even if encoding is missed in some places.

- Preconditions:
    - The application must render user-provided data dynamically in component templates without proper HTML encoding by default.
    - An attacker must find an injection point, such as a component property that is rendered in a template, and be able to control the value of this property, for example, through `unicorn:model` or server-side updates.
    - The vulnerable component must be accessible to potential victims.

- Source code analysis:
    1. **File: django_unicorn\views.py**: Review the `_render` method within `django_unicorn.views.__init__.py` and how context data is passed to the template rendering process in `component.render(request=request)`. Confirm if Django's default HTML auto-escaping is active and applied to all variables passed to the template context.
    2. **File: django_unicorn\templatetags\unicorn.py**: Analyze the `unicorn` template tag in `django_unicorn\templatetags\unicorn.py` and the `unicorn_errors` tag. Verify that any dynamic data rendered by these tags, especially error messages and component properties, is properly HTML encoded by default unless `safe` is explicitly used.
    3. **File: django_unicorn\utils.py**: Note that `sanitize_html` in `django_unicorn.utils.py` is designed for JSON output and uses `_json_script_escapes`. This is *not* general HTML escaping for XSS prevention in templates. Ensure that this function is not mistakenly relied upon as a general XSS mitigation for template rendering.
    4. **File: django_unicorn\components\unicorn_template_response.py**: Examine how the template is rendered in `UnicornTemplateResponse.render`. Check if BeautifulSoup or any other HTML processing steps might inadvertently decode or unescape HTML-encoded content before it's sent to the client. (Based on `pyproject.toml`, `beautifulsoup4` is a dependency, so its usage should be checked for potential XSS implications).
    5. **File: docs\source\views.md, docs\source\templates.md, docs\source\changelog.md**: Documentation mentions HTML encoding and `safe` option. Verify if the documentation accurately reflects the default safe encoding behavior and if the usage of `safe` is properly documented with security considerations. Review Changelog for CVE-2021-42053 fix details to fully understand the scope and limitations of the implemented mitigation and if it's comprehensive enough to cover all XSS vectors.
    6. **Visualization**: Data flow: User input (via `unicorn:model`, server-side property updates, etc.) -> Component state -> Template rendering (via `unicorn` template tag and Django template engine) -> HTML output to browser. XSS vulnerability point is at template rendering if user input in component state is not properly HTML-encoded before rendering by default.

- Security test case:
    1. **Identify Injection Point**: Find a component that renders user-controlled input in the template. A good starting point is to look for components that display properties bound with `unicorn:model` or any component that renders data that originates from user input or external sources. Example: a component displaying a `message` property.
    2. **Craft XSS Payload**: In the input field or mechanism that controls the target property, enter a standard XSS payload, such as `<script>alert('XSS')</script>`. Alternatively, use payloads like `<img src=x onerror=alert('XSS')>` or event attributes like `<div onmouseover="alert('XSS')">Hover me</div>` to test different contexts.
    3. **Trigger Component Update**: Cause the component to update and re-render so the payload is processed by the template engine. This might involve triggering an action, submitting a form, or any interaction that updates the component state and re-renders the template.
    4. **Verify XSS Execution**: Check if the JavaScript alert box (`alert('XSS')`) appears, or if the injected script executes in any way (e.g., by sending data to an attacker-controlled server).
    5. **Test with Different Contexts**: Test XSS payloads in various HTML contexts:
        - Inside HTML tags: `<p>{{ component.message }}</p>`
        - Inside HTML attributes: `<div title="{{ component.message }}">`
        - Inside JavaScript event handlers (if applicable, though less common in django-unicorn): `<button onclick="{{ component.message }}">`
        - Try different types of XSS payloads, including:
            - `<script>` tags
            - `<img>` tags with `onerror`
            - `<iframe>` tags
            - Event attributes (e.g., `onmouseover`, `onclick`)
            - URL-based XSS (if user input can influence URLs)
    6. **Bypass Attempts (if initial tests are encoded)**: If basic payloads are encoded, attempt to bypass encoding using common XSS bypass techniques:
        - Case variations (`<ScRiPt>`)
        - Encoded characters (`&#x3c;script&#x3e;`)
        - Double encoding
        - Context-specific bypasses
        - DOM-based XSS payloads (if DOM manipulation is involved)
    7. **Test `safe` Filter and `Meta.safe`**: Verify the behavior when `safe` filter or `Meta.safe` is used. Confirm that using `safe` indeed prevents encoding and allows script execution (if intended and correctly used). Ensure that *not* using `safe` results in proper encoding and prevents XSS by default. Check if removing `safe` where it is used re-introduces the vulnerability.
    8. **Expected Result**: If the vulnerability exists, the XSS payload will execute in the user's browser. If mitigated correctly, the payload should be rendered as harmless text, and JavaScript code should not execute unless `safe` is explicitly and intentionally used. Confirm that default behavior is safe HTML encoding.
