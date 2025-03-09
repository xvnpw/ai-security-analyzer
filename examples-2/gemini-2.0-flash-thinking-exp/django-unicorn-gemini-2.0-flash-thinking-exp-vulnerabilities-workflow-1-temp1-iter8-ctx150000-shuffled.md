## Combined Vulnerability List for django-unicorn Project

### Potential XSS vulnerability due to unsafe string formatting in template rendering

* Description:
    - An attacker could potentially inject malicious JavaScript code into component properties that are not properly sanitized before being rendered in the HTML. This risk is heightened when developers explicitly use features designed to bypass Django's default HTML escaping mechanisms.
    - This vulnerability is exposed when a developer uses `Meta.safe` attribute in a component or `safe` template filter in the template, intending to render HTML without escaping and assumes content is safe without proper sanitization.
    - Step 1: Identify a component and a property rendered in a template that is vulnerable to XSS.
    - Step 2: Craft a malicious input containing a JavaScript payload (e.g., `<img src=x onerror=alert(document.domain)>`).
    - Step 3: Inject the payload by manipulating input fields bound to component properties using `unicorn:model` or by crafting specific parameters for methods called via `unicorn:click` or similar directives.
    - Step 4: Trigger an action that updates the vulnerable property with the malicious payload. This could be a `syncInput` event or a `callMethod` action.
    - Step 5: The component re-renders, and because the output is marked as safe (via `Meta.safe` or `safe` filter) without sanitization, the JavaScript payload executes in the user's browser.

* Impact: Cross-site scripting (XSS). An attacker could execute arbitrary JavaScript code in the victim's browser, potentially leading to session hijacking, account takeover, website defacement, or redirection to malicious sites.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - Django's automatic HTML escaping is used by default in templates.
    - The `safe` Meta attribute and `safe` template filter are available to bypass encoding, implicitly suggesting developer awareness of XSS risks.
    - `django_unicorn.utils.sanitize_html` function is used to sanitize initial data passed to Javascript on initial render.

* Missing Mitigations:
    - User inputs that modify component properties dynamically through actions like `syncInput` and `callMethod` are not consistently sanitized before being re-rendered, especially when `Meta.safe` or `safe` template filter are used.
    - No explicit warning or guidance in the documentation about the security implications of using `safe` Meta class and when it is appropriate to use it safely.

* Preconditions:
    - A component renders a property influenced by user input.
    - The developer uses `Meta.safe` or the `safe` filter when rendering the user-influenced property.
    - User input can modify the component property via `unicorn:model` or `callMethod` actions.

* Source Code Analysis:
    - File: `django_unicorn\components\unicorn_template_response.py`
        - `UnicornTemplateResponse.render` method renders the component.
        - `get_frontend_context_variables` in `UnicornView` uses `sanitize_html` for initial data but not for subsequent updates.
        - Template rendering relies on Django's escaping, bypassed by `safe`.
    - File: `django_unicorn\views\message.py`
        - `_process_component_request` renders the component after action processing, but consistent sanitization is unclear for dynamically updated properties.
    - File: `django_unicorn\views\action_parsers\call_method.py`
        - `handle` processes `callMethod` actions and uses `set_property_value`.
    - File: `django_unicorn\views\action_parsers\utils.py`
        - `set_property_value` directly sets property values using `setattr` without sanitization, allowing malicious payloads if `safe` is used in templates.
    - Visualization:
        ```
        User Input --> HTTP Request (Action: syncInput/callMethod, Payload: malicious JS) --> django-unicorn view (message.py) --> Action Parser (call_method.py) --> set_property_value (utils.py) --> Component Property (malicious JS stored) --> UnicornTemplateResponse.render (unicorn_template_response.py) --> Template Rendering (property rendered UNSANITIZED due to 'safe' usage) --> HTML Response (malicious JS executes in browser)
        ```

* Security Test Case:
    - Step 1: Create a component `XssTestComponent` with a `safe` property `xss_payload`.
    - Step 2: Create `xss_test_component.html` to render `xss_payload` and include `<input unicorn:model="xss_payload">`.
    - Step 3: Create `xss_test.html` to render the component.
    - Step 4: Create `XssTestView` to render `xss_test.html`.
    - Step 5: Define URL pattern for `XssTestView`.
    - Step 6: Access page in browser.
    - Step 7: Input `<img src=x onerror=alert('XSS')>` in the input field.
    - Step 8: Trigger `syncInput` event.
    - Step 9: Observe alert box with 'XSS'.
    - Step 10: Inspect HTML source to confirm unescaped payload.

### Cross-Site Scripting (XSS) via Partial Updates

* Description:
    - An attacker can manipulate `unicorn:partial` targets in client-side requests to inject malicious HTML during partial updates.
    - Step 1: Craft a malicious payload for a component interaction that triggers a partial update.
    - Step 2: Manipulate the `unicorn:partial` target to point to a wider DOM element or a crafted element.
    - Step 3: The server processes the action and generates a response with a partial update.
    - Step 4: The response includes a crafted HTML payload with malicious JavaScript for the manipulated target.
    - Step 5: `morphdom` injects the malicious JavaScript into the DOM, leading to XSS.

* Impact: Cross-site scripting (XSS). An attacker can execute arbitrary JavaScript code, leading to account takeover, data theft, website defacement, redirection to malicious sites, and further attacks.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - Django-unicorn uses `morphdom` for DOM diffing and merging, designed to be secure.
    - Django templates auto-escape HTML content by default.
    - Documentation mentions HTML encoding and `Meta.safe` for opting out.
    - Tests exist for HTML encoding and `Meta.safe`.

* Missing Mitigations:
    - No server-side validation or sanitization of `unicorn:partial` targets.
    - No sanitization of HTML content in partial updates, relying solely on `morphdom` security.

* Preconditions:
    - Application uses Django-unicorn's partial updates (`unicorn:partial`).
    - No server-side validation of `unicorn:partial` targets or sanitization of partial update content.
    - Attacker can manipulate request parameters, especially `unicorn:partial` target.

* Source Code Analysis:
    - File: `django_unicorn/views/__init__.py` - `_process_component_request` handles partial updates.
    - Partial updates are processed, and `partials` are extracted from the action payload.
    - Target element selection using `BeautifulSoup` based on `unicorn:key`, `id`, or `id` from `unicorn:partial`.
    - DOM merging via `morphdom` on the client-side using `partial_doms` from the server response.
    - Vulnerability: Lack of server-side validation of client-provided `target`, `key`, `id` for partial updates, allowing manipulation for broader scope XSS.
    - File: `django_unicorn/static/unicorn/js/unicorn.js` - Client-side JavaScript handles `partials` and uses `morphdom`.

* Security Test Case:
    - Step 1: Create `PartialXssView` component with partial update functionality.
    - Step 2: Inspect network requests and identify AJAX POST for component interactions.
    - Step 3: Craft a malicious payload by modifying `actionQueue` with crafted `partials` array including `<script>` tag.
    - Step 4: Send modified AJAX request using `curl`, Postman, or browser tools.
    - Step 5: Verify XSS by checking if JavaScript code is executed in the browser.
    - Step 6: Expect JavaScript alert box to appear, confirming XSS via partial updates.

### Remote Code Execution via unsafe method argument parsing

* Description:
    - An attacker can achieve Remote Code Execution (RCE) by crafting a malicious `callMethod` action payload.
    - Step 1: Identify a component method that accepts arguments.
    - Step 2: Craft a `callMethod` action payload with malicious Python code disguised as a method argument.
    - Step 3: Inject the malicious payload within data structures like dictionaries or lists in the arguments.
    - Step 4: Send the crafted JSON payload to the `/unicorn/message/<component_name>` endpoint via POST request.
    - Step 5: Server-side `django-unicorn` code parses the payload using `eval_value` and `ast.literal_eval`.
    - Step 6: The injected payload executes during argument parsing, resulting in RCE.

* Impact: Critical. Arbitrary code execution on the server leading to full compromise, data breaches, data manipulation, and denial of service.

* Vulnerability Rank: Critical

* Currently Implemented Mitigations:
    - None. Relies on unsafe `ast.literal_eval` and `eval_value` for parsing untrusted input without sufficient sanitization.

* Missing Mitigations:
    - Input Sanitization and Validation: Strict server-side input validation for method arguments.
    - Avoid `eval()` and `ast.literal_eval`: Replace with safer parsing methods like `json.loads` and explicit validation.
    - Principle of Least Privilege: Run application with minimum privileges.
    - Web Application Firewall (WAF): Deploy WAF to detect malicious requests.

* Preconditions:
    - Application deployed and publicly accessible.
    - Component with a method accepting arguments triggerable by external users.
    - Attacker can send POST requests to `/unicorn/message` with crafted JSON payload.

* Source Code Analysis:
    - File: `django_unicorn\call_method_parser.py`
        - Function: `eval_value(value)` uses `ast.literal_eval` to parse values, which is unsafe for untrusted input and allows code injection through crafted payloads in data structures.
    - File: `django_unicorn\views\action_parsers\call_method.py`
        - Function: `_call_method_name` parses arguments using `eval_value`, making any method argument path vulnerable.

* Security Test Case:
    - Step 1: Setup Django-unicorn app with a component method accepting arguments (`HelloWorldView.set_name`).
    - Step 2: Access the application.
    - Step 3: Craft malicious JSON payload for `callMethod` action targeting `set_name` with RCE payload.
    - Step 4: Send the payload to `/unicorn/message/<component_name>`.
    - Step 5: Verify RCE by checking for file creation (`/tmp/unicorn_rce_test`) or using `whoami` command and inspecting server logs.

### Insecure Deserialization in Component Caching

* Description:
    - django-unicorn uses `pickle` to serialize and deserialize cached components, which is vulnerable to insecure deserialization.
    - Step 1: Components are cached using `pickle.dumps`.
    - Step 2: Cached components are retrieved and deserialized using `pickle.loads`.
    - Step 3: An attacker can replace cached component data with a malicious pickled payload.
    - Step 4: Upon retrieval and deserialization, the malicious payload executes arbitrary code.

* Impact: Remote Code Execution (RCE). Complete system compromise, data breaches, and severe security consequences.

* Vulnerability Rank: Critical

* Currently Implemented Mitigations:
    - None. Uses `pickle` without security measures.

* Missing Mitigations:
    - Replace `pickle`: Migrate to secure serialization like `json` or carefully use `dill`. Ideally avoid deserializing code from cache.
    - Implement data integrity checks: Use cryptographic signing or MACs for cached data integrity.
    - Explore alternative caching strategies: Minimize or eliminate code deserialization from cache, consider template fragment caching.

* Preconditions:
    - Component caching enabled (`UNICORN['CACHE_ALIAS']` configured).
    - Attacker can inject malicious pickled data into the cache backend (compromised cache system or other vulnerabilities).

* Source Code Analysis:
    - File: `django_unicorn\cacher.py`
        - `cache_full_tree` uses `cache.set` (implicit `pickle.dumps`).
        - `restore_from_cache` uses `cache.get` (implicit `pickle.loads`).
        - No sanitization or integrity checks before/after `pickle` operations.

* Security Test Case:
    - Step 1: Setup Django project with django-unicorn and non-DummyCache (e.g., `locmem`).
    - Step 2: Create `MaliciousComponent` with `__reduce__` for RCE on deserialization.
    - Step 3: Simulate cache poisoning by manually setting cache entry with malicious pickled payload.
    - Step 4: Trigger deserialization by sending a request to retrieve the cached component.
    - Step 5: Verify code execution by checking for file creation (`/tmp/unicorn_pwned`) on the server.

### Server-Side Template Injection via Component Arguments

* Description:
    - An attacker can inject template code via malicious component names or arguments in the `{% unicorn %}` template tag.
    - Step 1: Craft a malicious component name or component arguments for `{% unicorn %}` tag.
    - Step 2: Inject template code in component name or arguments.
    - Step 3: `django-unicorn` renders the component, executing the injected template code server-side.

* Impact: Server-Side Template Injection (SSTI). Arbitrary Python code execution, data breaches, server takeover, denial of service.

* Vulnerability Rank: Critical

* Currently Implemented Mitigations:
    - Relies on Django's template engine safety, no specific sanitization for component names/arguments beyond Django defaults.

* Missing Mitigations:
    - Input sanitization and validation for component names/arguments in `{% unicorn %}` tag.
    - Code review of component loading and rendering logic for SSTI vulnerabilities.
    - Security tests for SSTI in component rendering.

* Preconditions:
    - Application uses `django-unicorn`.
    - User-controlled input influences component name or arguments in `{% unicorn %}` tag.
    - Attacker can control template rendering context passed to `{% unicorn %}`.

* Source Code Analysis:
    - File: `templatetags/unicorn.py` (and `django_unicorn/templatetags/unicorn.py`)
        - `UnicornNode.render` takes component name and args directly from template string, resolved via `template.Variable`.
        - `UnicornView.create` uses these resolved values, potentially vulnerable to SSTI if unsanitized user input is used in `component_name` or `resolved_kwargs`.

* Security Test Case:
    - Step 1: Create Django view allowing user input to influence component arguments.
    - Step 2: Modify template to pass user input as component argument in `{% unicorn %}`.
    - Step 3: Access view with malicious payload in URL query parameter (e.g., `?arg=</p><p>Malicious Payload: {{settings.SECRET_KEY}}</p><p>`).
    - Step 4: Inspect rendered HTML for leaked `settings.SECRET_KEY` or sensitive info, confirming SSTI.
    - Step 5: Attempt more advanced payloads for code execution (e.g., `{% system 'ls -al' %}`).

### Insecure Direct Object Reference (IDOR) via Model Type Hinting in Method Arguments

* Description:
    - `django-unicorn` automatically fetches Django Model instances based on type hints in component methods, potentially leading to IDOR.
    - Step 1: Component method type-hinted with a Django Model.
    - Step 2: `django-unicorn` fetches model instance using argument value as primary key.
    - Step 3: If method lacks authorization checks, attacker can manipulate arguments (primary key) to access unauthorized model instances.

* Impact: Unauthorized data access and potential data manipulation.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - None. Relies on developers to implement authorization checks.

* Missing Mitigations:
    - Documentation highlighting IDOR risk with Model type hinting.
    - Secure coding guidelines and examples for authorization checks.
    - Security tests for IDOR vulnerabilities with Model type hinting.

* Preconditions:
    - Application uses `django-unicorn`.
    - Component method type-hinted with Django Model and takes a primary key argument from user input.
    - Component method uses fetched model instance without authorization checks.
    - Attacker can call the vulnerable method.

* Source Code Analysis:
    - File: `django_unicorn/views/action_parsers/call_method.py` - `_call_method_name` function.
        - Automatically retrieves Django Model instances using `objects.get()` based on user-provided value when type-hinted.
        - No framework-level authorization checks during model retrieval.

* Security Test Case:
    - Step 1: Create `SecretNote` Django model with `owner` field.
    - Step 2: Create `NoteComponentView` with `view_note(note: SecretNote)` method without authorization checks.
    - Step 3: Create template using component allowing `view_note` call with user input for note ID.
    - Step 4: Create two `SecretNote` instances, different owners.
    - Step 5: Login as user with access to only their own notes.
    - Step 6: Use component to try to view another user's note by providing their note ID.
    - Step 7: Observe if content of unauthorized note is displayed, confirming IDOR.
