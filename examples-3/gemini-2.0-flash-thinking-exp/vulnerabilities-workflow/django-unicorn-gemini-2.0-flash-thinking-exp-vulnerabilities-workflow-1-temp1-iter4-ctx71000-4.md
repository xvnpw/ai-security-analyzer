## Vulnerability List for django-unicorn Project

- Vulnerability Name: **Unsafe arbitrary Python code execution via `call_method_parser.py`**
- Description:
    - The `django-unicorn/call_method_parser.py` file is responsible for parsing method calls from strings received from the frontend.
    - The `parse_call_method_name` function uses `ast.parse` and `ast.literal_eval` to process these method calls, including arguments and keyword arguments.
    - An attacker could potentially craft a malicious method call string that, when parsed by `ast.parse` and `ast.literal_eval`, executes arbitrary Python code on the server.
    - Step-by-step trigger:
        1. An attacker intercepts or crafts a request to the `/unicorn/message` endpoint.
        2. In the request payload (likely within the `actionQueue` field, specifically in the `payload.name` for a `callMethod` action), the attacker injects a malicious string for the method name. This string is crafted to exploit the parsing logic in `parse_call_method_name`.
        3. The backend server, using django-unicorn, receives this request and calls `parse_call_method_name` to parse the method name and arguments.
        4. Due to the unsafe use of `ast.parse` and potentially `ast.literal_eval`, the malicious string is interpreted as Python code and executed by the server.
- Impact:
    - **Critical** - Remote Code Execution (RCE). Successful exploitation allows the attacker to execute arbitrary Python code on the server hosting the django-unicorn application. This can lead to complete compromise of the server, data breach, denial of service, and other severe security consequences.
- Vulnerability Rank: critical
- Currently implemented mitigations:
    - None apparent in the provided code. The code directly uses `ast.parse` on user-controlled input for method names. While `ast.literal_eval` is used on arguments, the initial `ast.parse` on the method name itself is the primary vulnerability.
- Missing mitigations:
    - **Input sanitization and validation:**  Strictly validate the method name and arguments received from the frontend. Use a whitelist of allowed methods and argument types. Do not directly parse arbitrary strings from user input as code.
    - **Secure parsing:** Instead of relying on `ast.parse` for potentially unsafe evaluation, implement a safer parsing mechanism.  For example, use regular expressions or a dedicated parsing library to extract method names and arguments in a controlled manner.
    - **Principle of least privilege:** Ensure the web server process running django-unicorn has minimal permissions to reduce the impact of RCE.
- Preconditions:
    - Publicly accessible instance of a django-unicorn application where actions can be triggered by external users (e.g., via button clicks or model updates).
    - The application must be using the vulnerable version of django-unicorn (or without proper mitigations applied).
- Source code analysis:
    - File: `django_unicorn/call_method_parser.py`
    - Function: `parse_call_method_name`
    ```python
    @lru_cache(maxsize=128, typed=True)
    def parse_call_method_name(
        call_method_name: str,
    ) -> Tuple[str, Tuple[Any, ...], Mapping[str, Any]]:
        """
        Parses the method name from the request payload into a set of parameters to pass to
        a method.
        ...
        """
        ...
        tree = ast.parse(method_name, "eval") # [!] Unsafe use of ast.parse
        statement = tree.body[0].value #type: ignore

        if tree.body and isinstance(statement, ast.Call):
            call = tree.body[0].value # type: ignore
            method_name = call.func.id
            args = [eval_value(arg) for arg in call.args]
            kwargs = {kw.arg: eval_value(kw.value) for kw.keywords}
        ...
        return method_name, tuple(args), MappingProxyType(kwargs)
    ```
    - The line `tree = ast.parse(method_name, "eval")` in `parse_call_method_name` function compiles the `method_name` string from the request into an AST using `ast.parse`. This is inherently unsafe as it allows parsing and potentially executing arbitrary Python code if the `method_name` is not strictly controlled. While arguments are processed with `eval_value` (which uses `ast.literal_eval`), the initial parsing of the method name itself with `ast.parse` allows for code injection.
- Security test case:
    - Pre-requisites:
        - Set up a django-unicorn application based on the documentation.
        - Create a component with at least one action that can be triggered from the frontend.
    - Steps:
        1. Identify the endpoint for unicorn requests, which is `/unicorn/message`.
        2. Use browser developer tools or a tool like `curl` to craft a POST request to the `/unicorn/message` endpoint.
        3. Set the `Content-Type` header to `application/json`.
        4. In the request body, create a JSON payload to trigger a `callMethod` action with a malicious method name. The structure should be similar to:
        ```json
        {
          "id": "testComponentId",
          "name": "testComponentName",
          "epoch": 1678886400,
          "checksum": "valid_checksum_will_be_needed",
          "actionQueue": [
            {
              "type": "callMethod",
              "payload": {
                "name": "__import__('os').system('touch /tmp/unicorn_pwned')",
                "args": [],
                "kwargs": {}
              },
              "partials": []
            }
          ],
          "data": {}
        }
        ```
        5. Replace `"testComponentId"` and `"testComponentName"` with the actual component ID and name.
        6. Generate a valid checksum for the `data` dictionary (which is empty `{}` in this case) using the `generate_checksum` function from `django_unicorn.utils`. Update the `"checksum"` field in the JSON payload with this generated checksum.
        7. Send the crafted POST request to the server.
        8. Check if the command injection was successful. In this example, verify if the file `/tmp/unicorn_pwned` was created on the server. (Note: `/tmp/unicorn_pwned` is just an example; a real attack could execute far more damaging commands).
