## Vulnerability List for django-unicorn Project

### 1. Cross-Site Scripting (XSS) via Unsafe Template Rendering and `safe` Option

- **Vulnerability Name:** Cross-Site Scripting (XSS) via Unsafe Template Rendering and `safe` Option
- **Description:**
    1. A developer uses the `safe` Meta option in a Django Unicorn component or the `safe` template filter to prevent HTML encoding for a specific component field or template variable.
    2. This field/variable is intended to display user-generated content, data from an external source, or data dynamically passed to component methods, and it is not properly sanitized.
    3. An attacker injects malicious JavaScript code into the user-generated content, external data source, or method arguments. This can be achieved through model binding (`unicorn:model`), action arguments, or direct manipulation of data sources.
    4. When the Django Unicorn component renders, the malicious JavaScript code is included in the HTML output without proper encoding because the `safe` option/filter is enabled for the field/variable.
    5. When a user views the page, the attacker's JavaScript code executes in their browser, potentially leading to account takeover, data theft, or other malicious actions.
- **Impact:** Execution of arbitrary JavaScript code in the victim's browser, leading to potential account compromise, sensitive data disclosure, or other malicious actions. Critical impact due to potential for complete account takeover and data breaches.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - By default, Django Unicorn HTML encodes all component field values to prevent XSS.
    - Developers must explicitly use the `safe` Meta option or `safe` template filter to disable HTML encoding for specific fields or template variables, indicating a conscious decision to bypass default encoding.
    - `sanitize_html` function in `django_unicorn/utils.py` is used for HTML escaping in JSON data sent to the frontend, but not for template rendering when `safe` is used.
- **Missing Mitigations:**
    - No built-in sanitization or escaping mechanism is enforced when using the `safe` Meta option or `safe` template filter.
    - Lack of clear and prominent documentation warning against using `safe` with unsanitized user-controlled data and recommending proper sanitization methods. Documentation doesn't adequately emphasize security risks of `safe`.
    - Absence of usage warnings during component rendering when `safe` is used to highlight potential risks.
    - No built-in, recommended sanitization mechanism specifically designed for use with `safe`.
- **Preconditions:**
    - A Django Unicorn component is implemented with a field or template variable that uses the `safe` Meta option or `safe` template filter.
    - This field/variable displays user-generated content, data from an external source, or data from method arguments.
    - The developer does not implement proper sanitization of the data before rendering it in the component.
    - Attacker can control data rendered with `safe` through `unicorn:model`, action arguments or other data sources.
- **Source Code Analysis:**
    - In `django_unicorn/views.py` within the `UnicornView.render_component` method, the component's template is rendered. Django template engine uses `safe` filter/attribute to bypass HTML encoding.
    - `views.md` documentation explains `safe` Meta attribute and `safe` template filter.
    - `changelog.md` mentions default HTML encoding from v0.36.0, highlighting the risk when `safe` is used improperly.
    - `components/unicorn_template_response.py` uses Django's template engine which respects `safe` filter/attribute.
    - `templatetags/unicorn.py` orchestrates component rendering, relying on Django's default escaping behavior unless `safe` is used.
    - `tests/test_utils.py` - `test_sanitize_html` shows `sanitize_html` escapes `<script>`.
    - `test_set_property_from_data.py` shows how component properties can be updated, including with potentially malicious payloads.

    **Visualization:**
    ```
    User Input --> Component Property/Template Variable --> Template Rendering (with 'safe') --> HTML Response --> User Browser (XSS)
    ```
- **Security Test Case:**
    1. Create a Django Unicorn component with a field named `unsafe_content` and add `safe = ("unsafe_content",)` to the `Meta` class or use `{{ unsafe_content|safe }}` in template.
    2. In the component's template, render the `unsafe_content` field: `{{ unsafe_content }}` or `{{ unsafe_content|safe }}` depending on where `safe` option is used.
    3. Create a view that renders a template containing this Unicorn component.
    4. In the component's view, set `unsafe_content` to a malicious JavaScript payload, for example: `<img src='x' onerror='alert(\"XSS Vulnerability\")'>`.
    5. Access the view in a web browser.
    6. Observe that the JavaScript alert `XSS Vulnerability` is executed, demonstrating the XSS vulnerability.

### 2. Cross-Site Scripting (XSS) via Unsafe HTML Attribute Rendering

- **Vulnerability Name:** Cross-Site Scripting (XSS) via Unsafe HTML Attribute Rendering
- **Description:**
    1. An attacker can inject malicious JavaScript code by controlling data that is used to dynamically construct HTML attributes within a Django Unicorn component template.
    2. Identify a Django Unicorn component that uses user-controlled data to dynamically construct HTML attributes, e.g., `<div data-attribute="{{ dynamic_attribute }}">`.
    3. Inject malicious JavaScript code into the user-controlled data, for example: `\` onclick="alert('XSS-attribute')\` `.
    4. The template will render the HTML attribute without proper escaping, resulting in `<div data-attribute=" onclick="alert('XSS-attribute')" ">`.
    5. When a user interacts with the element (e.g., clicks on the div), the injected JavaScript code will execute in their browser, leading to XSS.
- **Impact:** High. Successful XSS can allow an attacker to execute arbitrary JavaScript code in the victim's browser within the context of the vulnerable web application. This can lead to session hijacking, account takeover, defacement, redirection to malicious sites, or information theft.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - Django Unicorn attempts to HTML-encode updated field values by default to prevent XSS (changelog v0.36.0).
    - `safe` Meta option and `safe` template filter exist to explicitly allow unencoded values for tag content.
    - `sanitize_html` function in `django_unicorn/utils.py` used for escaping HTML content in some contexts.
- **Missing Mitigations:**
    - Django Unicorn does not automatically escape data rendered within HTML *attributes* by default. Escaping mechanism focuses on HTML tag content.
    - No clear documentation warning against using user-controlled data to construct HTML attributes dynamically without manual escaping.
    - No automatic attribute escaping during template rendering.
- **Preconditions:**
    - A Django Unicorn component template must use user-controlled data to construct HTML attributes directly.
    - The developer must not be manually escaping the data used in HTML attributes.
    - Attacker can control data used for HTML attribute via `unicorn:model` or other mechanisms.
- **Source Code Analysis:**
    - `django_unicorn/utils.py` - `sanitize_html` for HTML content escaping (tag content).
    - Files do not explicitly show `sanitize_html` or similar escaping is automatically applied to data in HTML attributes.
    - `test_safe_html_entities_not_encoded` in `test_process_component_request.py` confirms `safe` bypasses HTML encoding for tag content, highlighting potential attribute context escaping issue.
    - `example/unicorn/components/text_inputs.py` and `test_sanitize_html` in `test_utils.py` show awareness of XSS risks in general, but attribute escaping is missing.
- **Security Test Case:**
    1. Create a Django Unicorn component with a property `attribute_value` and a template with `<div id="target" dynamic-attribute="{{ attribute_value }}">`.
    2. Navigate to page with component in browser.
    3. Enter payload `\` onclick="alert('XSS-attribute')\` ` in input field bound to `attribute_value`.
    4. Trigger component update.
    5. Inspect rendered HTML, observe attribute: `dynamic-attribute=" onclick="alert('XSS-attribute')" "`.
    6. Click "Test" div, alert "XSS-attribute" should appear, confirming XSS.

### 3. Potential Deserialization Vulnerability via Cached Components

- **Vulnerability Name:** Potential Deserialization Vulnerability via Cached Components (Pickle)
- **Description:**
    1. Django Unicorn uses Django's caching framework to store component state, especially with the experimental serialization feature enabled.
    2. If the cache backend is compromised, an attacker might inject malicious serialized component data into the cache.
    3. Craft a malicious serialized component state using pickle format.
    4. Inject malicious pickled data into cache under component cache key.
    5. When application restores component from cache using `restore_from_cache` in `django_unicorn/cacher.py`, malicious data will be deserialized.
    6. Deserialization of untrusted pickle data can lead to code execution.
- **Impact:** High to Critical. Deserialization vulnerabilities can lead to Remote Code Execution (RCE), allowing complete server compromise.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - Django Unicorn uses Django's cache framework with inherent security considerations.
    - Serialization is experimental and disabled by default.
    - Documentation warns against dummy caching in production for serialization.
- **Missing Mitigations:**
    - Consider safer serialization format than pickle, if feasible.
    - Implement integrity checks for cached component data (digital signatures).
    - More explicit documentation warning about deserialization risks with caching, especially with experimental serialization, and recommendations for secure cache backend configurations.
- **Preconditions:**
    - Experimental serialization feature enabled (`UNICORN['SERIAL']['ENABLED'] = True`).
    - Attacker must be able to inject data into Django cache backend (infrastructure compromise).
- **Source Code Analysis:**
    - `django_unicorn/cacher.py` uses `pickle.dumps` and `pickle.loads` for serialization/deserialization.
    - `CacheableComponent`, `cache_full_tree`, `restore_from_cache` functions in `django_unicorn/cacher.py` handle caching.
    - `example/project/settings.py` shows `UNICORN['SERIAL']['ENABLED'] = True` in example config, implying intended use and associated risk.
    - Pickle deserialization in `restore_from_cache` becomes exploit entry point if cache access control is bypassed.
- **Security Test Case:**
    - _Note:_ Requires simulating cache compromise (outside web app testing).
    1. Setup Django Unicorn project with `UNICORN['SERIAL']['ENABLED'] = True` and cache backend.
    2. Run app, trigger component caching.
    3. Manually access cache backend (e.g., Redis CLI).
    4. Identify cached component key.
    5. Craft malicious pickle payload (e.g., `__reduce__` for RCE). Serialize using `pickle.dumps`.
    6. Replace cached component data with malicious payload in cache.
    7. Trigger component restoration from cache in app (e.g., page refresh).
    8. Observe if malicious code from pickle payload executes on server (RCE confirmation).

### 4. Logic Manipulation via Unsafe Data Handling in `eval_value` and `set_property_from_data`

- **Vulnerability Name:** Logic Manipulation via Unsafe Data Handling in `eval_value` and `set_property_from_data`
- **Description:**
    1. Attacker crafts malicious payloads in `call_method_name` requests or property update data.
    2. `parse_call_method_name` (`django_unicorn\call_method_parser.py`) and `set_property_from_data` (`django_unicorn\views\utils.py`) process payloads.
    3. `parse_call_method_name` uses `ast.parse` and `eval_value` with `ast.literal_eval`. `set_property_from_data` handles property updates, including deserializing into Django models/querysets.
    4. **Vulnerability:** `ast.literal_eval` and `set_property_from_data` prevent direct code execution, but type coercion and logic manipulation are possible. Unexpected data structures (lists, dicts) can cause unintended behavior if component logic relies on implicit type coercion without validation. Vulnerable if component expects specific types/structures but receives manipulated ones.
    5. Manipulated arguments/property data can lead to unintended actions, data corruption, logic bypasses if component methods/setters lack type/content validation after `eval_value` or `set_property_from_data`.
- **Impact:** High. Logic manipulation can lead to data corruption, unintended actions, or bypassing application-level security checks. Severity depends on component's actions and input validation robustness. Naive component logic using unvalidated values can lead to significant impact.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - `ast.literal_eval` (in `eval_value`) restricts evaluation to literals, reducing RCE risk in method args.
    - Type hints in components provide *potential* input validation *if enforced by developer*. Django-unicorn doesn't enforce type hints for security.
    - Documentation encourages Django forms for validation, a best practice but not built-in mitigation.
- **Missing Mitigations:**
    - Lack of *enforced* input validation/sanitization in core `parse_call_method_name`, `eval_value`, `set_property_from_data`. These don't prevent logic manipulation via type coercion and data structures.
    - Lack of clear documentation guidance on validating method args and property data beyond general Django forms recommendation. Need to emphasize validating *type* and *structure* parsed by `eval_value` and `set_property_from_data`.
- **Preconditions:**
    - Django Unicorn components handle user input via actions, methods, and property updates.
    - Component methods/property handling rely on type coercion from `eval_value`/`set_property_from_data` and lack input validation beyond type hints.
    - Attacker sends crafted requests to trigger actions or property updates with malicious data.
- **Source Code Analysis:**
    - `django_unicorn\call_method_parser.py`: `eval_value` uses `ast.literal_eval` for parsing. `parse_call_method_name` calls `eval_value` for arguments.
    - `django_unicorn\views\utils.py`: `set_property_from_data` handles model/queryset property updates, uses `_construct_model` to instantiate models from dicts.
    - `django_unicorn\typer.py`: `_construct_model` instantiates model using `model_class(**init_kwargs)` with user-provided dict, potential issue.

    **Visualization (Method Call):**
    ```mermaid
    graph LR
        A[Request Payload (call_method_name)] --> B(parse_call_method_name);
        B --> C{ast.parse};
        C --> D{eval_value (arg 1)};
        C --> E{eval_value (arg 2)};
        D --> G[Component Method Call];
        E --> G;
        G --> H[Application Logic & Potential Vulnerability (no validation)];
    ```
    **Visualization (Property Update):**
    ```mermaid
    graph LR
        A[Request Payload (property update data)] --> B(set_property_from_data);
        B --> C{_construct_model (Model/QuerySet)};
        C --> D[Model Instantiation (user-provided dict)];
        D --> E[Component Property Update];
        E --> F[Application Logic & Potential Vulnerability (no validation)];
    ```
- **Security Test Case:**
    1. Create `VulnerableComponent` with `process_data` and `update_flavor` methods, and `flavor_property` (Model). No input validation within methods.
    2. Test normal cases for "Process Data" and "Update Flavor" buttons and user input.
    3. Craft malicious payload for "Process User Method Input", inject list instead of dict to `process_data` via `call_method_name`. Observe "Invalid data format" or errors.
    4. Craft malicious payload for "Update Flavor with User Property Input", inject list/malformed dict for `flavor_property` in update data. Observe server response and component behavior. Check `flavor_property.name` for unexpected updates/errors.
    5. Success: Demonstrate component logic deviates when manipulated data provided, indicating vulnerability due to insufficient validation after `eval_value`/`set_property_from_data`. Show argument/property manipulation causes unintended behavior because of lacking validation in component logic.

### 5. Potential Remote Code Execution via Insecure Method Argument Parsing (Re-emergence of CVE-2021-42053)

- **Vulnerability Name:** Potential Remote Code Execution via Insecure Method Argument Parsing
- **Description:**
    1. An attacker could inject arbitrary Python code through arguments passed to component methods due to insecure parsing using `ast.literal_eval` in `django_unicorn\call_method_parser.py`.
    2. Craft a malicious payload for method arguments in `unicorn:click` action to execute arbitrary Python when parsed by `ast.literal_eval`.
    3. Trigger action from frontend.
    4. Server-side code in `django_unicorn\call_method_parser.py` parses payload with `ast.literal_eval`.
    5. If payload bypasses `ast.literal_eval`'s safe evaluation, RCE occurs on server.
- **Impact:** Critical. Successful exploitation allows arbitrary Python code execution on server, leading to complete server compromise.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - None in provided code. Relies on `ast.literal_eval` intended for safe evaluation, but bypassable.
- **Missing Mitigations:**
    - Input sanitization and validation of method arguments *before* parsing.
    - Use more secure parsing mechanism, strictly limiting allowed expressions.
    - Consider safer alternative to `ast.literal_eval` or strict allowlisting of argument types/values.
- **Preconditions:**
    - Application uses Django Unicorn components with methods accepting frontend arguments.
    - Attacker can interact with frontend components to trigger actions.
- **Source Code Analysis:**
    - `django_unicorn\call_method_parser.py`: `eval_value` uses `ast.literal_eval` for parsing. `parse_call_method_name` parses method name and args, calling `eval_value` for each argument.
    - `django_unicorn\typer.py`: `cast_value` function uses `CASTERS` from `call_method_parser.py`, confirming `ast.literal_eval` core parsing.
    - Tests in `django_unicorn\tests\call_method_parser\test_parse_args.py` and `django_unicorn\tests\views\action_parsers\call_method\test_call_method_name.py` confirm `eval_value` usage for argument parsing.
- **Security Test Case:**
    1. Create `RceTestView` component with `execute_code` method that `eval(code)`.
    2. Template with button `unicorn:click="execute_code('__import__(\\'os\\').system(\\'touch /tmp/pwned\\')')"` to trigger RCE.
    3. Render page in browser, click "Trigger RCE".
    4. Check server for creation of `/tmp/pwned`, indicating RCE success.

### 6. Cross-Site Scripting (XSS) Vulnerability via Unsafe HTML Attribute Rendering (Re-emergence)

- **Vulnerability Name:** Cross-Site Scripting (XSS) Vulnerability via Unsafe HTML Attribute Rendering
- **Description:**
    1. Django Unicorn might be vulnerable to XSS if it doesn't properly escape HTML attributes during re-rendering.
    2. User-controlled data in dynamically set HTML attributes in templates, not properly escaped server-side/client-side.
    3. Control component property used for HTML attribute.
    4. Inject malicious JavaScript payload into property: `"><img src=x onerror=alert('XSS')>`.
    5. Trigger component re-render (action/model update).
    6. If HTML attribute not escaped, payload injected into HTML, executed in user's browser.
- **Impact:** High. XSS allows arbitrary JavaScript execution, session hijacking, cookie theft, website defacement, malicious redirection.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - Changelog v0.36.0: CVE-2021-42053 fix, "responses HTML encoded", `safe` for opt-out. General HTML encoding mitigation.
    - `django_unicorn\utils.py`, `django_unicorn\components\unicorn_template_response.py`: `sanitize_html` for JSON script content escaping, unclear for HTML attributes.
- **Missing Mitigations:**
    - Ensure *all* dynamically rendered HTML attributes are *always* HTML escaped by default.
    - Review templates/component logic, fix any unescaped user-controlled data in attributes.
    - Implement Content Security Policy (CSP) headers for further XSS mitigation.
- **Preconditions:**
    - Django Unicorn components with templates dynamically rendering HTML attributes using properties.
    - Attacker can influence data populating these properties (direct/indirect manipulation).
- **Source Code Analysis:**
    - `django_unicorn\views.py`, `django_unicorn\templatetags\unicorn.py`, frontend JS code relevant to dynamic updates/rendering, check HTML attribute escaping.
- **Security Test Case:**
    1. Create `XssAttrTestView` component, template with `<div dynamic-attribute="{{ dynamic_attr }}">`, input bound to `dynamic_attr`.
    2. Render page in browser.
    3. Enter payload `"><img src=x onerror=alert('XSS')>` in input.
    4. Trigger component update.
    5. Inspect rendered HTML source, `dynamic-attribute` attribute.
    6. If attribute value unescaped, `alert('XSS')` executes, XSS confirmed.

### 7. Insecure Deserialization leading to Potential Vulnerabilities (using orjson)

- **Vulnerability Name:** Insecure Deserialization leading to Potential Vulnerabilities (using orjson)
- **Description:**
    1. Django Unicorn uses `orjson` for JSON serialization/deserialization (`django_unicorn\serializer.py`).
    2. Insecure deserialization vulnerabilities possible depending on how deserialized data is used, even with `orjson` (considered generally safe).
    3. Craft malicious JSON payload to cause unintended behavior when deserialized by `orjson` and used by server-side component logic.
    4. Send payload to server in Unicorn action/model update request.
    5. Insecure processing of deserialized data by component logic could lead to exploitation.
- **Impact:** High. Impact depends on deserialized data usage. Critical operations can lead to data corruption or code execution (combined with other issues).
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None evident in serializer code. Security relies on safe usage of deserialized data in application logic.
- **Missing Mitigations:**
    - Input validation and sanitization of deserialized data *before* use in sensitive operations.
    - Checks to ensure deserialized data conforms to expected schema/types.
    - Secure coding practices to prevent insecure usage of deserialized data in component methods/logic.
- **Preconditions:**
    - Application uses Django Unicorn and processes deserialized data from frontend requests.
    - Attacker can send crafted JSON payloads in Unicorn requests.
- **Source Code Analysis:**
    - `django_unicorn\serializer.py`: `loads` function uses `orjson.loads` for deserialization.
    - Security implication depends on how deserialized data is used in `django_unicorn\views\utils.py`, `django_unicorn\views\__init__.py`, `django_unicorn\views\action_parsers\`.
    - `django_unicorn\views\utils.py`: `set_property_from_data` instantiates dataclasses: `value = type_hint(**value)`. Unsafe dataclass constructor can cause insecure deserialization. `cast_value` and type casting also related.
- **Security Test Case:**
    1. Create `DeserializeTestView` component using Django Model `Flavor` as property.
    2. Template with input bound to `flavor.name`.
    3. Render page in browser.
    4. Intercept POST request when `flavor.name` updated.
    5. Craft malicious JSON payload for `flavor` property in request data (unexpected types, database errors, inject unexpected fields).
    6. Send modified request.
    7. Observe server response/app behavior: errors, unexpected data changes, signs of insecure deserialization.

### 8. Information Disclosure via Insecure Django Model Serialization

- **Vulnerability Name:** Information Disclosure via Insecure Django Model Serialization
- **Description:**
    Django Unicorn default serialization of Django Models exposes all model fields in HTML source. Sensitive info (API keys, PII) in models is revealed to anyone viewing page source.
- **Impact:** High. External attacker can view page source and access sensitive model information. Identity theft, financial loss, reputational damage.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - Documentation warns of model exposure, suggests `Meta.exclude` or `Meta.javascript_exclude` to limit fields.
    - Documentation suggests customizing model serialization.
- **Missing Mitigations:**
    - Default should *not* serialize entire Django Model. Require explicit specification of fields to serialize.
    - Setting to globally enforce secure serialization strategy.
    - Prominent documentation warnings about default model serialization risks.
- **Preconditions:**
    - Django Unicorn component uses Django Model as class variable.
    - Django Model contains sensitive information.
    - Component rendered on public web page.
- **Source Code Analysis:**
    - `django_unicorn\serializer.py`: `_get_model_dict(model: Model)` serializes Django models.
    - Uses `serialize("json", [model])` to serialize *entire* model instance.
    - Serialized data embedded in HTML, sent to client.
- **Security Test Case:**
    1. Create `SecretModel` Django Model with `secret_key` (sensitive info).
    2. Create `SecretComponentView` component, `secret_data: SecretModel`, initialize in `mount`.
    3. Template renders `SecretComponent` (`{% unicorn 'secret-component' %}`).
    4. Access page in browser, view page source.
    5. Search for `secret_key` value ("ThisIsASecretKey").
    6. Observe `secret_key` in HTML source within component's initial data (information disclosure).
```html
<!-- templates/index.html -->
{% load unicorn %}
<html><head>{% unicorn_scripts %}</head><body>{% csrf_token %}{% unicorn 'secret-component' %}</body></html>
```
```python
# components/secret_component.py
from django_unicorn.components import UnicornView
from django.db import models
class SecretModel(models.Model): secret_key = models.CharField(max_length=255, default="ThisIsASecretKey")
class SecretComponentView(UnicornView): secret_data: SecretModel = None; def mount(self): self.secret_data = SecretModel.objects.create()
```
```python
# views.py
from django.shortcuts import render
from .components import secret_component; def index(request): return render(request, 'index.html')
```
```python
# urls.py
from django.urls import path; from .views import index; from django.conf import settings; from django.conf.urls.static import static; from django.urls import include
urlpatterns = [path('', index, name='index'),path("unicorn/", include("django_unicorn.urls")),]
if settings.DEBUG: urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
```
Run Django, access index, view source, search "ThisIsASecretKey" - should be in JSON.
```html
...
<script>
    Unicorn.setData('secret-component', {"secret_data": {"pk": 1, "secret_key": "ThisIsASecretKey"}});
</script>
...
```
