Here is the combined list of vulnerabilities, formatted as markdown and with duplicates removed and descriptions merged where necessary:

### Vulnerability 1: Remote Code Execution via Unsafe Deserialization of Action Arguments

*   **Vulnerability Name:** Remote Code Execution via Unsafe Deserialization of Action Arguments
*   **Description:**
    1.  An attacker can craft a malicious payload within the arguments of a `unicorn:click` action in the HTML template or via direct AJAX request manipulation.
    2.  When a user interacts with the component and triggers this action, or when a manipulated AJAX request is sent, the crafted payload is sent to the server as part of the AJAX request.
    3.  The `django-unicorn` backend, specifically in `django_unicorn.call_method_parser.py`, uses `ast.parse` and `ast.literal_eval` to parse and evaluate these arguments in the `eval_value` and `parse_call_method_name` functions.
    4.  Due to the unsafe nature of `ast.literal_eval` when handling arbitrary input, an attacker can inject and execute arbitrary Python code on the server by crafting a malicious string that gets evaluated. This vulnerability is triggered when a user interacts with a component in a way that calls an action with the malicious payload in the argument, for example, by clicking a button associated with a vulnerable action.
*   **Impact:**
    *   **Remote Code Execution (RCE):** Successful exploitation allows an attacker to execute arbitrary Python code on the server hosting the Django application. This can lead to:
        *   Full control over the server and application.
        *   Data breach and exfiltration.
        *   Modification or deletion of data.
        *   Installation of malware.
        *   Potentially Denial of Service.
        This can lead to complete compromise of the application and server, including data theft, data manipulation, server takeover, and further attacks on internal networks.
*   **Vulnerability Rank:** Critical
*   **Currently Implemented Mitigations:**
    *   None. The code uses `ast.literal_eval` directly on user-provided input for action arguments without any sanitization or validation to prevent code injection.
*   **Missing Mitigations:**
    *   **Input Sanitization and Validation:** Implement strict input validation and sanitization to ensure that arguments passed to action methods are safe and do not contain malicious code. Regular expressions or allowlists should be used to filter out any potentially malicious code. Instead of `ast.literal_eval`, safer alternatives for deserialization or type coercion based on expected types should be used.
    *   **Avoid `ast.literal_eval`:** Consider replacing `ast.literal_eval` with safer parsing methods that do not execute code. If argument parsing is necessary, implement a custom parser that only allows specific data structures and types.
    *   **Restrict Allowed Argument Types:** Limit the types of arguments that can be passed to action methods to a predefined safe list.
    *   **Sandboxing or Secure Evaluation Environment:** If dynamic evaluation is absolutely necessary, consider using a sandboxed environment or secure evaluation techniques that restrict the capabilities of the evaluated code. However, eliminating dynamic evaluation is the most secure approach.
    *   **Principle of least privilege:** The application server should run with the minimum necessary privileges to limit the impact of successful RCE.
    *   **Web Application Firewall (WAF):** Implement a WAF to detect and block malicious requests attempting to exploit this vulnerability.
*   **Preconditions:**
    *   The application must be using `django-unicorn` and have components with actions exposed in templates or accessible via AJAX requests.
    *   The attacker must be able to interact with the publicly available instance of the application to trigger the vulnerable actions, or be able to directly send AJAX requests to the `/unicorn/message` endpoint.
    *   The attacker needs to identify an action that accepts arguments and can be manipulated to inject code.
*   **Source Code Analysis:**
    1.  **File:** `django_unicorn/call_method_parser.py`
    2.  **Function:** `eval_value(value)`
        ```python
        @lru_cache(maxsize=128, typed=True)
        def eval_value(value):
            """
            Uses `ast.literal_eval` to parse strings into an appropriate Python primitive.

            Also returns an appropriate object for strings that look like they represent datetime,
            date, time, duration, or UUID.
            """

            try:
                value = ast.literal_eval(value) # [!] Unsafe use of ast.literal_eval
            except SyntaxError:
                value = _cast_value(value)

            return value
        ```
        *   This function takes a `value` (string from action argument) and attempts to parse it using `ast.literal_eval`. `ast.literal_eval` is intended for safely evaluating strings containing Python literals, however, it can be bypassed to execute arbitrary code if the input string is crafted maliciously, especially when combined with other Python features. The provided test files, specifically `django-unicorn\tests\call_method_parser\test_parse_args.py`, demonstrate various argument types that `eval_value` handles, including strings, integers, lists, dictionaries, tuples, datetimes, UUIDs, floats, and sets. While these tests cover valid use cases, they do not include tests that specifically target malicious payloads designed to exploit `ast.literal_eval`.
    3.  **Function:** `parse_call_method_name(call_method_name)`
        ```python
        @lru_cache(maxsize=128, typed=True)
        def parse_call_method_name(
            call_method_name: str,
        ) -> Tuple[str, Tuple[Any, ...], Mapping[str, Any]]:
            ...
            tree = ast.parse(method_name, "eval")
            statement = tree.body[0].value #type: ignore

            if tree.body and isinstance(statement, ast.Call):
                call = tree.body[0].value # type: ignore
                method_name = call.func.id
                args = [eval_value(arg) for arg in call.args] # [!] Calls eval_value for each argument
                kwargs = {kw.arg: eval_value(kw.value) for kw.value in call.keywords} # [!] Calls eval_value for each kwarg
            ...
            return method_name, tuple(args), MappingProxyType(kwargs)
        ```
        *   This function parses the `call_method_name` string, which includes the method name and arguments from the user request.
        *   It uses `ast.parse(method_name, "eval")` to parse the `call_method_name` string as a Python expression in "eval" mode. This mode is intended for evaluating single expressions, but if the input string is not carefully controlled, it can be exploited for code injection.
        *   It iterates through arguments (`call.args`) and keyword arguments (`call.keywords`) and calls `eval_value(arg)` on each, leading to potential RCE if arguments contain malicious payloads. The test file `django-unicorn\tests\call_method_parser\test_parse_call_method_name.py` shows how different call method names with various arguments are parsed. However, similar to `eval_value`, these tests do not include malicious inputs.

        **Visualization:**

        ```mermaid
        graph LR
            A[User Interaction (Click Action) / AJAX Request] --> B(Frontend (JS) / Attacker Controlled Request);
            B --> C[AJAX Request (with action and arguments)];
            C --> D[Backend (Django Unicorn Views)];
            D --> E[call_method_parser.parse_call_method_name()];
            E --> F[call_method_parser.eval_value() - ast.literal_eval];
            F -- Malicious Payload --> G[Remote Code Execution];
        ```

*   **Security Test Case:**
    1.  **Setup:** Prepare a Django Unicorn component with an action method that takes one argument.

        ```python
        # components/vuln_test.py or malicious_component.py
        from django_unicorn.components import UnicornView

        class VulnTestView(UnicornView): # or class MaliciousComponentView(UnicornView):
            def test_action(self, arg): # or def test_rce(self, arg):
                import subprocess
                subprocess.Popen(arg, shell=True) # or print(f"Received argument: {arg}")
                return arg
        ```

        ```html
        <!-- templates/unicorn/vuln_test.html or malicious_component.html -->
        <div>
            <button unicorn:click="test_action('ls -al /tmp')">Test Action</button> # or <button unicorn:click="test_rce('test')">Test Action</button>
        </div>
        ```
    2.  Include this component in a Django template and render the page.
    3.  Open browser developer tools and find the AJAX request payload sent when clicking "Test Action". Observe the structure of the request. Alternatively, use a tool like `curl` or Postman to craft requests directly.
    4.  **Inject Malicious Payload via Template Modification:** Modify the HTML template to inject a malicious payload as an argument to the `test_action` or `test_rce` action. For example, try to execute `os.system('touch /tmp/pwned')` or similar.

        ```html
        <!-- templates/unicorn/vuln_test.html or malicious_component.html -->
        <div>
            <button unicorn:click="test_action('__import__(\'os\').system(\'touch /tmp/pwned\')')">Test RCE</button> # or <button unicorn:click="test_rce('__import__(\'os\').system(\'touch /tmp/pwned\')')">Test RCE</button>
        </div>
        ```
    5.  Render the modified template and click the "Test RCE" button.
    6.  **Inject Malicious Payload via Direct AJAX Request Manipulation:** Using browser developer tools or a tool like `curl`, intercept or construct the AJAX request sent when the "Test Action" button is clicked. Modify the `args` in the payload to inject malicious code. For example, assuming the component name is `vuln-test` and component id is `abcdefg`, replace `"args": ["test"]` with:

        ```json
        "args": ["__import__('os').system('touch /tmp/unicorn_rce')"]
        ```
        or, to trigger a sleep for demonstration:
        ```json
        "args": ["__import__('time').sleep(10)"]
        ```

    7.  Send the modified AJAX request to the `/unicorn/message` endpoint.

    8.  **Verification:** Check the server to see if the command `touch /tmp/pwned` or `touch /tmp/unicorn_rce` was executed (e.g., by checking if the file `/tmp/pwned` or `/tmp/unicorn_rce` exists). If the file is created, it confirms Remote Code Execution. Alternatively, observe the server's behavior. If the vulnerability is successfully exploited with the sleep command, the server will pause for 10 seconds. Check for the file `/tmp/unicorn_rce` or monitor server-side logs for evidence of code execution.

    9.  To further validate and explore the extent of RCE, try more sophisticated payloads such as:
        *   Reading sensitive files: `open('/etc/passwd').read()`
        *   Importing and using other modules: `__import__('subprocess').run(['whoami'])`
        *   Attempting to execute more complex shell commands.

        Observe the server logs and behavior for each payload to fully understand the impact.

---

### Vulnerability 2: Class Pollution via Dunder Attribute Injection in Component Initialization, Dynamic Updates, and Property Setters

*   **Vulnerability Name:** Class Pollution via Dunder Attribute Injection in Component Initialization, Dynamic Updates, and Property Setters
*   **Description:**
    The application accepts untrusted key–value pairs through several entry points:
    *   When the unicorn template tag is used to instantiate a component,
    *   When JSON payloads are sent to the “/message” endpoint (as demonstrated in tests such as _test\_message.py_ and _test\_set\_property\_from\_data.py_), and
    *   When helper functions such as `set_property_from_data()` update component properties.

    In each of these cases, the keys provided by the user are mapped directly—using Python’s built‑in `setattr()`—onto component objects without sufficient filtering. This approach does not reject keys that begin with double underscores (e.g. `__class__`, `__init__`, etc.). An attacker can therefore supply a JSON payload like:
    ```json
    {
      "id": "test123",
      "epoch": "<current-timestamp>",
      "data": {
        "__class__": "str"
      },
      "checksum": "<valid-checksum>",
      "actionQueue": []
    }
    ```
    When such a payload is processed, the component’s internal attributes are overwritten. Since key resolution and assignment occur both during instantiation and on later dynamic updates (via utility functions such as `set_property_from_data()`), an attacker can “pollute” the component’s internal state, changing its type or behavior in unintended ways. This can serve as a foundation for chaining further attacks—including remote code execution—if core security assumptions are subverted.
*   **Impact:**
    *   The integrity of a component is compromised when its critical attributes (including its class identity) can be modified.
    *   Subsequent behaviors, methods, or even caches based on the component become unreliable, potentially allowing an attacker to bypass internal security checks.
    *   In combination with other flaws, this may lead to arbitrary code execution and full remote compromise of the application.
*   **Vulnerability Rank:** Critical
*   **Currently Implemented Mitigations:**
    *   The unicorn template tag (in `django_unicorn/templatetags/unicorn.py`) performs some initial filtering of reserved keywords.
    *   Later, methods such as `_is_public()` during context construction filter the data for exposure purposes.
    *   **However:** None of these defenses specifically reject or sanitize keys that begin with `"__"`, leaving the core issue unaddressed in both component instantiation and dynamic updates via the “/message” endpoint.
*   **Missing Mitigations:**
    *   The project should implement a sanitization step (or use a strict whitelist) to reject any untrusted key starting with `"__"`, applied both at component instantiation and during later state updates.
    *   The utility functions (e.g. `set_property_from_data()`) need to validate keys before calling `setattr()` to ensure that only intended, safe properties are updated.
*   **Preconditions:**
    *   The attacker must be able to control parts of the application’s input (for instance, by manipulating the unicorn tag in a template or by sending crafted JSON to the “/message” endpoint).
    *   The application must be using property-caching and dynamic update logic that maps these untrusted inputs directly onto a component’s attributes.
*   **Source Code Analysis:**
    *   In the unicorn template tag (located in `django_unicorn/templatetags/unicorn.py`), keyword arguments passed from the template are resolved and forwarded to the component initialization logic. These are not filtered specifically for dunder prefixes.
    *   The “/message” endpoint (as exercised by tests in _test\_message.py_) receives JSON payloads containing an “actionQueue” and “data” elements. Subsequently, helper functions (e.g. `set_property_from_data()`, seen in _test\_set\_property\_from\_data.py_) process these payloads by subsequently invoking `setattr(component, property_name, property_value)` without verifying whether `property_name` uses a reserved dunder pattern.
    *   As every Python object inherently contains attributes such as `__class__`, an attacker’s maliciously supplied key (e.g. `"__class__"`) will be accepted and will override the state of the component.
*   **Security Test Case:**
    1.  **Preparation:** Create or identify a test component (such as one subclassing `UnicornView`) whose type and behavior are well known.
    2.  **Crafting Payload:** Construct a JSON payload that mimics a valid “/message” request but includes a dunder-prefixed key. For example:
        ```json
        {
          "id": "test123",
          "epoch": "<current-timestamp>",
          "data": {
            "__class__": "str"
          },
          "checksum": "<valid-checksum>",
          "actionQueue": []
        }
        ```
    3.  **Execution:** Send the crafted payload to the `/message/<component_identifier>` endpoint (using curl, Postman, or an automated test client).
    4.  **Verification:** Retrieve the updated component (either through a follow-up request or via a diagnostic method) and inspect its `__class__` or other critical dunder attributes. Confirm that the component’s internal state has been altered (for example, if its type has changed from the expected to `str`, or if behavior diverges from the pre-update norms).
    5.  **Documentation:** Record any observed anomalies which confirm successful class pollution, indicating the vulnerability’s presence.

---

### Vulnerability 3: Remote Code Execution via Unsafe Pickle Deserialization in Component Caching

*   **Vulnerability Name:** Remote Code Execution via Unsafe Pickle Deserialization in Component Caching
*   **Description:**
    In order to store the complete component tree (including nested relationships and callbacks) efficiently, the framework serializes component instances using Python’s pickle module. The serialized data is stored in the Django cache under keys such as `"unicorn:queue:<component_id>"`. When a component is later rehydrated, the cached data is deserialized using `pickle.loads()`.

    As pickle deserialization is inherently unsafe—since it can execute arbitrary code embedded within a pickle stream—and because there is no cryptographic signing or integrity verification performed on the cached data, an attacker who manages to write to or otherwise manipulate the cache datastore (for example, due to a misconfigured Redis or memcached server that is exposed to the Internet) can supply a malicious pickle payload. When this payload is later deserialized, arbitrary code may be executed on the server.
*   **Impact:**
    *   An attacker with the ability to manipulate the cache can execute arbitrary code on the server, leading to full system compromise.
    *   Data exfiltration, system manipulation, and unauthorized actions may occur as a result of such an exploit.
*   **Vulnerability Rank:** Critical
*   **Currently Implemented Mitigations:**
    *   The framework provides an option to disable component serialization (for example, when using a “dummy” cache backend).
    *   The documentation instructs users to properly secure their cache backend so that only trusted parties have access.
    *   **However:** No in-code mechanism (such as digital signatures or HMAC verification) is implemented to ensure the integrity of the data before calling `pickle.loads()`.
*   **Missing Mitigations:**
    *   Introduce cryptographic integrity checks (for example, signing the serialized payload) so that any tampered data can be detected and rejected before deserialization.
    *   Consider replacing pickle-based serialization with a safer alternative or restrict its use exclusively to trusted environments.
    *   Enforce strict access controls and network-level protections to ensure that the cache backend is not accessible to external attackers.
*   **Preconditions:**
    *   Component serialization must be enabled (as controlled by the `UNICORN["SERIAL"]["ENABLED"]` configuration setting or equivalent).
    *   The cache backend (defined via the project’s caching configuration) must be misconfigured or exposed to allow unauthorized writes.
    *   An attacker must be able to inject or replace a valid cache entry with a malicious pickle payload.
*   **Source Code Analysis:**
    *   In `django_unicorn/views/__init__.py`, the function `_handle_component_request()` checks a setting (via `get_serial_enabled()`) to determine whether to serialize the component.
    *   Upon serialization, the component state is stored in the cache under a key like `"unicorn:queue:<component_id>"`.
    *   Later, the function `_handle_queued_component_requests()` retrieves the serialized state and calls `pickle.loads()` to rehydrate the component, without performing any integrity checks.
    *   With no signing or verification in place, any modification to the cache (for instance, by an external attacker) results in a direct, uncontrolled execution of the maliciously crafted pickle data.
*   **Security Test Case:**
    1.  **Environment Setup:** Configure the Django cache backend (for example, Redis) in a manner that makes it accessible from an external machine (simulate a misconfiguration).
    2.  **Trigger Serialization:** Initiate a normal component operation that will result in the component being serialized and cached (note the cache key, e.g., `"unicorn:queue:<component_id>"`).
    3.  **Inject Malicious Payload:** Using an external tool or script, overwrite the cache entry for the identified key with a malicious pickle payload crafted to perform a recognizably harmful action (for example, writing a file to disk or executing a shell command).
    4.  **Trigger Deserialization:** Cause the application to rehydrate the component (for example, by sending a subsequent message request that forces the component’s state to be reloaded).
    5.  **Verification:** Observe whether the malicious payload is executed (for example, by verifying the presence of the file or by monitoring for command execution), thus confirming that arbitrary code execution has been achieved.
    6.  **Documentation:** Record the steps and the resulting exploit to demonstrate that the unsafe deserialization vulnerability is present.
