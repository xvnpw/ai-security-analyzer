### Vulnerability 1: Remote Code Execution via Unsafe Deserialization of Action Arguments

* Vulnerability Name: Remote Code Execution via Unsafe Deserialization of Action Arguments
* Description:
    1. An attacker can craft a malicious payload within the arguments of a `unicorn:click` action in the HTML template.
    2. When a user interacts with the component and triggers this action, the crafted payload is sent to the server as part of the AJAX request.
    3. The `django-unicorn` backend, specifically in `django_unicorn.call_method_parser.py`, uses `ast.parse` and `ast.literal_eval` to parse and evaluate these arguments in the `eval_value` and `parse_call_method_name` functions.
    4. Due to the unsafe nature of `ast.literal_eval` when handling arbitrary input, an attacker can inject and execute arbitrary Python code on the server by crafting a malicious string that gets evaluated.
* Impact:
    - **Remote Code Execution (RCE):** Successful exploitation allows an attacker to execute arbitrary Python code on the server hosting the Django application. This can lead to complete compromise of the application and server, including data theft, data manipulation, server takeover, and further attacks on internal networks.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations:
    - None. The code uses `ast.literal_eval` directly on user-provided input for action arguments without any sanitization or validation to prevent code injection.
* Missing Mitigations:
    - **Input Sanitization and Validation:** Implement strict input validation and sanitization to ensure that arguments passed to action methods are safe and do not contain malicious code.  Instead of `ast.literal_eval`, safer alternatives for deserialization or type coercion based on expected types should be used.
    - **Restrict Allowed Argument Types:** Limit the types of arguments that can be passed to action methods to a predefined safe list.
    - **Sandboxing or Secure Evaluation Environment:** If dynamic evaluation is absolutely necessary, consider using a sandboxed environment or secure evaluation techniques that restrict the capabilities of the evaluated code. However, eliminating dynamic evaluation is the most secure approach.
* Preconditions:
    - The application must be using `django-unicorn` and have components with actions exposed in templates.
    - The attacker must be able to interact with the publicly available instance of the application to trigger the vulnerable actions.
* Source Code Analysis:
    1. **File:** `django_unicorn\call_method_parser.py`
    2. **Function:** `eval_value(value)`
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
    - This function takes a `value` (string from action argument) and attempts to parse it using `ast.literal_eval`. `ast.literal_eval` is intended for safely evaluating strings containing Python literals, however, it can be bypassed to execute arbitrary code if the input string is crafted maliciously, especially when combined with other Python features. The provided test files, specifically `django-unicorn\tests\call_method_parser\test_parse_args.py`, demonstrate various argument types that `eval_value` handles, including strings, integers, lists, dictionaries, tuples, datetimes, UUIDs, floats, and sets. While these tests cover valid use cases, they do not include tests that specifically target malicious payloads designed to exploit `ast.literal_eval`.
    3. **Function:** `parse_call_method_name(call_method_name)`
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
    - This function parses the `call_method_name` string, which includes the method name and arguments from the user request.
    - It iterates through arguments (`call.args`) and keyword arguments (`call.keywords`) and calls `eval_value(arg)` on each, leading to potential RCE if arguments contain malicious payloads. The test file `django-unicorn\tests\call_method_parser\test_parse_call_method_name.py` shows how different call method names with various arguments are parsed. However, similar to `eval_value`, these tests do not include malicious inputs.

    **Visualization:**

    ```mermaid
    graph LR
        A[User Interaction (Click Action)] --> B(Frontend (JS));
        B --> C[AJAX Request (with action and arguments)];
        C --> D[Backend (Django Unicorn Views)];
        D --> E[call_method_parser.parse_call_method_name()];
        E --> F[call_method_parser.eval_value() - ast.literal_eval];
        F -- Malicious Payload --> G[Remote Code Execution];
    ```

* Security Test Case:
    1. Create a Django Unicorn component with an action method that simply prints the received argument.
        ```python
        # malicious_component.py
        from django_unicorn.components import UnicornView

        class MaliciousComponentView(UnicornView):
            def test_rce(self, arg):
                print(f"Received argument: {arg}")
        ```
        ```html
        <!-- malicious_component.html -->
        <div>
            <button unicorn:click="test_rce('test')">Test Action</button>
        </div>
        ```
    2. Include this component in a Django template and render the page.
    3. Open browser developer tools and find the AJAX request payload sent when clicking "Test Action". Observe the structure of the request.
    4. Modify the HTML template to inject a malicious payload as an argument to the `test_rce` action. For example, try to execute `os.system('touch /tmp/pwned')` or similar.
        ```html
        <!-- malicious_component.html -->
        <div>
            <button unicorn:click="test_rce('__import__(\'os\').system(\'touch /tmp/pwned\')')">Test RCE</button>
        </div>
        ```
    5. Render the modified template and click the "Test RCE" button.
    6. Check the server to see if the command `touch /tmp/pwned` was executed (e.g., by checking if the file `/tmp/pwned` exists). If the file is created, it confirms Remote Code Execution.
    7. To further validate and explore the extent of RCE, try more sophisticated payloads such as:
        - Reading sensitive files: `open('/etc/passwd').read()`
        - Importing and using other modules: `__import__('subprocess').run(['whoami'])`
        - Attempting to execute more complex shell commands.

        Observe the server logs and behavior for each payload to fully understand the impact.
