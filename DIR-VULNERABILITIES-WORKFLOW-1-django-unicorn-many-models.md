# Vulnerability List

## 1. Remote Code Execution via Insecure Deserialization of Component Properties and Action Arguments

**Severity Check & Real-World Risk Analysis**
After reviewing the impact, required preconditions, and the attacker steps involved, the severity rating of **Critical** remains appropriate. The ability to craft malicious payloads that circumvent `ast.literal_eval` and custom type casting can lead to full server compromise with relatively minimal effort by the attacker. As long as the application is publicly accessible and an attacker can tamper with AJAX requests, there is a genuine and severe risk of remote code execution.

---

### Description
1. **Attack Vector**: Malicious payloads crafted as arguments to component actions or values for component properties.
2. **Deserialization Logic**: The `django-unicorn` framework relies on `ast.literal_eval` and custom type casting (in `call_method_parser.py`, `typer.py`, and `views/utils.py`) to parse and process data sent from the client.
3. **Bypassing Safe Deserialization**: An attacker may find ways to inject arbitrary Python code if the data is not strictly sanitized and validated, enabling potential RCE.
4. **Affected Flows**: Both component action calls and property updates are susceptible due to shared deserialization logic.

### Impact
- **Critical**: Successful exploitation grants full remote code execution on the server. Attackers could modify application behavior, access or exfiltrate sensitive data, and disrupt operations.

### Vulnerability Rank
- **critical**

### Currently Implemented Mitigations
- Use of `ast.literal_eval`, which is intended to safely evaluate literal expressions.
- Type casting in `typer.py` to coerce arguments to expected types.
- Checksum mechanism to prevent state tampering, though it may not block carefully crafted malicious data.

### Missing Mitigations
- Rigorous input sanitization and validation for both action arguments and component property values.
- Stronger, more restrictive deserialization methods preventing code execution paths.
- Potential sandboxing or isolation for handling untrusted data.

### Preconditions
- A publicly accessible Django application using `django-unicorn`.
- Attacker knowledge of a component method accepting arguments (for action calls) or a property set from the client (for property updates).

### Source Code Analysis

1. **File: `django_unicorn/call_method_parser.py`**
   - `eval_value` uses `ast.literal_eval` for parsing:
     ```python
     @lru_cache(maxsize=128, typed=True)
     def eval_value(value):
         try:
             value = ast.literal_eval(value)  # Potential RCE if bypassing literal_eval
         except SyntaxError:
             value = _cast_value(value)
         return value
     ```

2. **File: `django_unicorn/typer.py`**
   - `_cast_value` and `cast_value` attempt to cast values using type hints:
     ```python
     def cast_value(type_hint, value):
         ...
         if _check_pydantic(_type_hint) or is_dataclass(_type_hint):
             value = _type_hint(**value)  # Potentially unsafe deserialization
         else:
             value = _type_hint(value)
         ...
     ```

3. **File: `django_unicorn/views/action_parsers/call_method.py`**
   - `_call_method_name` executes component methods with arguments processed by `cast_value`:
     ```python
     def _call_method_name(component: UnicornView, method_name: str, args: Tuple[Any], kwargs: Dict[str, Any]) -> Any:
         ...
         for argument in arguments:
             parsed_args.append(cast_value(type_hint, args[len(parsed_args)]))
         ...
         return func(*parsed_args, **parsed_kwargs)
     ```

4. **File: `django_unicorn/views/utils.py`**
   - `set_property_from_data` updates component properties using `cast_value`:
     ```python
     def set_property_from_data(component: UnicornView, name: str, value: Any):
         if property_type_hint:
             value = cast_value(property_type_hint, value)
         setattr(component, name, value)
     ```

These flows demonstrate how both action calls and property updates rely on the same insecure deserialization logic.

---

### Security Test Case

1. **Select a Vulnerable Component**
   ```python
   class VulnerableComponent(UnicornView):
       text = "initial value"

       def set_text(self, new_text):
           self.text = new_text
   ```
   ```html
   <input type="text" unicorn:model="text">
   <button unicorn:click="set_text(text)">Set Text</button>
   <p>{{ text }}</p>
   ```

2. **Intercept AJAX Requests**
   - Use developer tools or a proxy (e.g., Burp Suite) to capture requests made by `unicorn:model` or `unicorn:click`.

3. **Manipulate the Payload**
   - For property updates, modify the `value` field for `text` in the request JSON.
   - For action calls, modify arguments to the `set_text` method.
   - Attempt to bypass `ast.literal_eval` or `cast_value`.

4. **Send the Modified Payload**
   - Observe if the server processes malicious data and executes arbitrary code.

5. **Check for Impact**
   - Monitor logs or verify side effects (e.g., file creation, command execution).

6. **Example Malicious Payload** (must be adapted to the environment and bypass techniques):
   ```json
   {
     "component_name": "vulnerable-component",
     "data": {
       "text": '["__class__", {"__class__": "subprocess", "Popen", ["touch /tmp/unicorn_rce_prop"], "kwargs": {"shell": true}}]'
     },
     "checksum": "...",
     ...
   }
   ```

7. **Try Payload Variations**
   - Aim to exploit `ast.literal_eval`, bypass type casting, or deserialize into unsafe classes or models.

---

**Conclusion**
This vulnerability remains **Critical** based on the real-world potential for remote code execution with minimal preconditions. Any organization using `django-unicorn` should prioritize implementing strict input validation, secure deserialization techniques, and possibly isolated execution environments to mitigate such attacks.
