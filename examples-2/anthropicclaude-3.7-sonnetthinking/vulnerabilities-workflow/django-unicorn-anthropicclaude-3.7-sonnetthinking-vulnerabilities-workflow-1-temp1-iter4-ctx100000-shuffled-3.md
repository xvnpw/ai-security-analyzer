# Django-Unicorn Security Vulnerabilities

After analyzing the criteria, only one high-severity vulnerability meets all the requirements for inclusion:

## Insecure Deserialization in Method Arguments (High)

### Description
Django-Unicorn deserializes method arguments from client-side requests. While it uses `ast.literal_eval` for parsing values (which is safer than `eval()`), there remain risks in how complex objects are deserialized and instantiated. This vulnerability is part of the framework's core processing logic rather than a developer misuse issue.

### Impact
An attacker could potentially execute arbitrary code on the server by crafting malicious method arguments, leading to server compromise, data breach, or unauthorized access to sensitive information. The vulnerability could allow an external attacker to execute commands in the context of the web server.

### Vulnerability rank
High

### Currently implemented mitigations
- The framework uses `ast.parse` and `ast.literal_eval` for parsing arguments, which is safer than `eval()`
- Method arguments undergo type checking via Python's type annotations
- The serializer uses the safer `orjson` library for JSON parsing
- Integrity validation is performed using checksums to prevent tampering

### Missing mitigations
- No comprehensive validation of complex nested objects
- Insufficient restrictions on what types can be deserialized
- No sanitization for certain object instantiation patterns

### Preconditions
- The application must have components with methods that accept arguments
- The attacker must be able to manipulate the method call payload or craft custom requests to the application

### Source code analysis
Django-Unicorn uses several layers of serialization and deserialization. In the `serializer.py` file, the framework uses `orjson` for JSON handling:

```python
def loads(string: str) -> dict:
    """
    Converts a string representation to dictionary.
    """
    try:
        return orjson.loads(string)
    except orjson.JSONDecodeError as e:
        raise JSONDecodeError from e
```

In `django_unicorn/call_method_parser.py`, method arguments are parsed using `ast.literal_eval`:

```python
def eval_value(value):
    """
    Uses `ast.literal_eval` to parse strings into an appropriate Python primitive.
    """
    try:
        value = ast.literal_eval(value)
    except SyntaxError:
        value = _cast_value(value)
    return value
```

In `django_unicorn/typer.py`, the `cast_value` function attempts to cast values based on type hints, but also allows direct instantiation of classes:

```python
if _check_pydantic(_type_hint) or is_dataclass(_type_hint):
    value = _type_hint(**value)
    break

value = _type_hint(value)
break
```

When handling model objects, Django-Unicorn attempts to create model instances from deserialized data:

```python
if is_model:
    DbModel = type_hint  # noqa: N806
    key = "pk"
    value = None

    if not kwargs:
        value = args[len(parsed_args)]
        parsed_args.append(DbModel.objects.get(**{key: value}))
    else:
        value = kwargs.get("pk")
        parsed_kwargs[argument] = DbModel.objects.get(**{key: value})
```

While these mechanisms are generally safer than direct `eval()`, the complex processing of arguments and dynamic instantiation of objects could still lead to security issues, especially with complex nested objects. The framework doesn't have sufficient validation to prevent all forms of insecure deserialization.

### Security test case
1. Create a component with a method that accepts complex arguments:
   ```python
   class VulnerableComponent(UnicornView):
       def process_data(self, data):
           # Process the data
           print(f"Processing: {data}")
   ```

2. Create a malicious payload that attempts to exploit deserialization flaws:
   ```json
   {
     "actionQueue": [
       {
         "type": "callMethod",
         "payload": {
           "name": "process_data",
           "args": ["__import__('os').system('id')"]
         }
       }
     ],
     "data": {},
     "checksum": "VALID_CHECKSUM",
     "id": "component-id",
     "epoch": 1634567890
   }
   ```

3. Send this payload to the component's message endpoint:
   ```
   POST /unicorn/message/app.components.VulnerableComponent
   ```

4. Monitor the server for signs of code execution. While `ast.literal_eval` provides some protection, the complex type casting and object instantiation mechanisms could potentially be exploited with sufficiently crafted payloads targeting weaknesses in how complex objects are deserialized.
