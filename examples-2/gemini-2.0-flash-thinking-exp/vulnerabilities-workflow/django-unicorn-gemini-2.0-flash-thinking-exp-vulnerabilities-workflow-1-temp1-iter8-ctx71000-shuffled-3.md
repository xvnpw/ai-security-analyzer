- Vulnerability name: Remote Code Execution via Method Call Parsing
  - Description:
    1. An attacker sends a crafted POST request to the `/message/{component_name}` endpoint.
    2. The request includes a `callMethod` action with a malicious `name` payload.
    3. The `name` payload is designed to exploit the `parse_call_method_name` function in `django_unicorn/call_method_parser.py`.
    4. The `parse_call_method_name` function uses `ast.parse` with mode `eval` to parse the method name and arguments.
    5. By injecting malicious Python code into the `name` payload, the attacker can execute arbitrary Python code on the server when `ast.parse` is called.
    6. This can lead to complete compromise of the server.
  - Impact: Remote Code Execution (RCE). An attacker can execute arbitrary Python code on the server hosting the Django application. This allows for full system compromise, data exfiltration, and denial of service.
  - Vulnerability rank: Critical
  - Currently implemented mitigations:
    - Checksum validation of the request data. However, this mitigation only ensures data integrity and does not prevent code injection if the vulnerable parsing logic is used on the data itself.
  - Missing mitigations:
    - Input sanitization and validation for `call_method_name` in `parse_call_method_name` to prevent code injection.
    - Avoid using `ast.parse` with `eval` mode for parsing user-provided input. Consider using safer parsing techniques or whitelisting allowed characters and patterns for method names and arguments.
  - Preconditions:
    - A publicly accessible instance of a Django application using django-unicorn.
    - The application must expose a component that handles `callMethod` actions.
  - Source code analysis:
    ```python
    # File: django_unicorn/call_method_parser.py
    @lru_cache(maxsize=128, typed=True)
    def parse_call_method_name(
        call_method_name: str,
    ) -> Tuple[str, Tuple[Any, ...], Mapping[str, Any]]:
        """
        Parses the method name from the request payload into a set of parameters to pass to
        a method.
        ...
        """
        tree = ast.parse(method_name, "eval") # Vulnerable code: ast.parse with mode='eval'
        statement = tree.body[0].value #type: ignore

        if tree.body and isinstance(statement, ast.Call):
            call = tree.body[0].value # type: ignore
            method_name = call.func.id
            args = [eval_value(arg) for arg in call.args]
            kwargs = {kw.arg: eval_value(kw.value) for kw.keywords}

        # ...
        return method_name, tuple(args), MappingProxyType(kwargs)
    ```
    - The `parse_call_method_name` function in `django_unicorn/call_method_parser.py` uses `ast.parse(method_name, "eval")`.
    - The `method_name` string is directly taken from the request payload, specifically from the `name` field of the `callMethod` action.
    - `ast.parse(..., mode='eval')` when used with untrusted input is inherently dangerous as it allows execution of arbitrary code. An attacker can inject Python code into the `call_method_name` string.
    - For example, a malicious `call_method_name` could be `import os; os.system('malicious_command')` which, when parsed by `ast.parse(..., "eval")`, would execute the `os.system('malicious_command')` command on the server.

  - Security test case:
    1. Setup a Django project with django-unicorn integrated and a publicly accessible view with a Unicorn component.
    2. Create a Unicorn component with a simple method (e.g., `test_method`) that can be called from the frontend.
    3. Using `curl` or a similar tool, send a POST request to the `/message/{component_name}` endpoint. Replace `{component_name}` with the actual component name.
    4. Set the `Content-Type` header to `application/json`.
    5. Include the following JSON payload in the request body:
    ```json
    {
      "id": "testComponentId",
      "name": "testComponentName",
      "epoch": 1678886400,
      "data": {},
      "checksum": "...",
      "actionQueue": [
        {
          "type": "callMethod",
          "payload": {
            "name": "import os; os.system('touch /tmp/unicorn_rce');test_method"
          }
        }
      ]
    }
    ```
    - Replace `"..."` with the correct checksum of the `data` field (which is an empty dictionary in this case, so checksum should be easy to generate for empty dict).
    - Adjust `component_name` and `testComponentId` accordingly.
    6. Send the request to the publicly accessible instance of the application.
    7. Check the server to see if the file `/tmp/unicorn_rce` was created. If the file exists, it confirms successful Remote Code Execution.
    8. Additionally, monitor the application logs for any error messages or exceptions that might indicate failed attempts or successful exploitation.
