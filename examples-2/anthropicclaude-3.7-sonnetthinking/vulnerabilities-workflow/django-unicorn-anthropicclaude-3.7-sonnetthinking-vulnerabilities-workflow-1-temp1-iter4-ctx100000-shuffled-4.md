# Vulnerability Report for Django-Unicorn

Based on my analysis of the project files, I've identified the following high-severity vulnerabilities that meet the specified criteria:

## 1. Server-Side Object Instantiation via Type Hints

- **Vulnerability Name**: Server-Side Object Instantiation via Type Hints

- **Description**: Django-Unicorn dynamically instantiates Python classes based on type hints from component definitions and data from HTTP requests. The framework uses the component's type hints to determine how to deserialize the data. This creates a security risk where an attacker can trigger the instantiation of classes with dangerous side effects in their constructors by sending specially crafted data.

  The vulnerability exists in multiple places:
  1. `cast_value` in `typer.py` which instantiates classes directly with user-provided data
  2. `set_property_from_data` in `views/utils.py` which uses `cast_value` for updating component properties
  3. `_construct_model` in `typer.py` which creates Django model instances

  For example, in `typer.py`:
  ```python
  if _check_pydantic(_type_hint) or is_dataclass(_type_hint):
      value = _type_hint(**value)
      break

  value = _type_hint(value)
  break
  ```

- **Impact**: Depending on the classes that can be instantiated, this vulnerability could lead to:
  - Arbitrary code execution
  - Information disclosure
  - Database corruption
  - Server compromise

- **Vulnerability Rank**: High

- **Currently Implemented Mitigations**: The framework includes a checksum validation mechanism that helps protect against tampering with the data. This validation uses HMAC with Django's SECRET_KEY to verify the integrity of incoming data.

- **Missing Mitigations**:
  1. Implement stricter validation of class instantiation
  2. Maintain a whitelist of allowed classes that can be instantiated
  3. Provide clear documentation about the risks of using type hints for classes with side effects

- **Preconditions**:
  1. A component must define properties with type hints for classes with dangerous side effects
  2. The attacker must be able to craft inputs that trigger those side effects
  3. The attacker must be able to bypass checksum validation or the SECRET_KEY must be compromised

- **Source Code Analysis**:
  The issue begins in the `typer.py` file in the `cast_value` function. When a request comes in to update a component property, this function is called to convert the incoming data to the appropriate type based on the component's type hints:

  ```python
  def cast_value(type_hint, value):
      # ...
      for _type_hint in type_hints:
          # ...
          if _check_pydantic(_type_hint) or is_dataclass(_type_hint):
              value = _type_hint(**value)
              break

          value = _type_hint(value)
          break
  ```

  This directly uses the passed-in value to instantiate objects. While there is a check to avoid directly instantiating Django models:

  ```python
  if issubclass(_type_hint, Model):
      continue
  ```

  Other Python classes are instantiated without restriction. This means if a component has a property with a type hint pointing to a class with dangerous side effects in its constructor, an attacker could craft data to trigger those effects.

  The call chain typically flows from a user request through:
  1. The message view which processes the request
  2. `set_property_value` in `action_parsers/utils.py` which handles property updates
  3. `cast_attribute_value` in `typer.py` which applies type casting
  4. `cast_value` in `typer.py` which performs the actual instantiation

- **Security Test Case**:
  1. Create a component with a property type-hinted as a class with dangerous side effects:
     ```python
     class DangerousClass:
         def __init__(self, cmd=None):
             if cmd:
                 import subprocess
                 subprocess.run(cmd, shell=True)

     class VulnerableComponent(UnicornView):
         dangerous: DangerousClass = None
     ```
  2. Deploy the application and obtain a valid session with authentication
  3. Craft a payload to update the `dangerous` property:
     ```json
     {
       "data": {"dangerous": {"cmd": "id > /tmp/pwned"}},
       "checksum": "<valid_checksum>",
       "id": "<component_id>",
       "epoch": 123456789,
       "actionQueue": [
         {
           "type": "syncInput",
           "payload": {"name": "dangerous", "value": {"cmd": "id > /tmp/pwned"}}
         }
       ]
     }
     ```
  4. Send the payload to the `/message/vulnerable-component` endpoint
  5. Verify that the command was executed by checking for the existence of `/tmp/pwned`

## 2. Unintended Method Calls with Attacker-Controlled Arguments

- **Vulnerability Name**: Unintended Method Calls with Attacker-Controlled Arguments

- **Description**: Django-Unicorn allows calling methods on components with user-provided arguments. When a request comes in, the framework locates the method on the component and calls it with the provided arguments. If a component exposes methods with dangerous side effects, an attacker can call those methods with crafted arguments to trigger unintended actions.

  For example, the framework allows calling arbitrary component methods through the `callMethod` action type. While these methods are intended for user interaction, they may have harmful side effects if called with unexpected arguments.

- **Impact**: Depending on the specific methods exposed, this vulnerability could lead to:
  - Unauthorized database operations (create, read, update, delete)
  - Information disclosure
  - Access control bypass
  - Business logic subversion

- **Vulnerability Rank**: High

- **Currently Implemented Mitigations**: The framework includes a checksum validation mechanism that helps protect against tampering with the method name or arguments. This validation uses HMAC with Django's SECRET_KEY to verify the integrity of incoming data.

- **Missing Mitigations**:
  1. Implement a whitelist of methods that can be called from the frontend
  2. Add deeper validation of method arguments
  3. Provide documentation on securing component methods

- **Preconditions**:
  1. A component must expose methods with dangerous side effects
  2. The attacker must be able to craft arguments that trigger those side effects
  3. The attacker must be able to bypass checksum validation or the SECRET_KEY must be compromised

- **Source Code Analysis**:
  The issue is primarily in the `call_method.py` file in the `_call_method_name` function:

  ```python
  def _call_method_name(component, method_name, args=None, kwargs=None):
      # ...
      component_method = getattr(component, method_name, None)

      if not component_method:
          return None

      # Type-cast arguments based on type hints
      # ...

      return component_method(*method_args, **method_kwargs)
  ```

  This directly calls the method on the component with the provided arguments. The framework does type-cast arguments based on the method's type hints, but this doesn't prevent calling methods with dangerous side effects.

  Looking at examples in the codebase, there are several component methods that could be abused:

  ```python
  def delete(self, flavor_to_delete: Flavor):
      flavor_to_delete.delete()
      self.refresh_flavors()
  ```

  If an attacker can call this method with controlled arguments, they might be able to manipulate the database in unintended ways.

  The message handling flow:
  1. The message view receives a request with an action queue
  2. For each action of type "callMethod", it extracts the method name and arguments
  3. It calls `_call_method_name` which invokes the method with the provided arguments
  4. The method executes with attacker-controlled inputs

- **Security Test Case**:
  1. Create a component with a method that has dangerous side effects:
     ```python
     class VulnerableComponent(UnicornView):
         sensitive_data = "secret information"

         def delete_all(self):
             # Delete all records in a table
             MyModel.objects.all().delete()

         def get_data(self, data_key=None):
             # This could leak sensitive information
             if data_key == "sensitive_data":
                 return self.sensitive_data
             return None
     ```
  2. Deploy the application and authenticate as a regular user
  3. Craft a payload to call the `delete_all` method:
     ```json
     {
       "data": {},
       "checksum": "<valid_checksum>",
       "id": "<component_id>",
       "epoch": 123456789,
       "actionQueue": [
         {
           "type": "callMethod",
           "payload": {"name": "delete_all()"}
         }
       ]
     }
     ```
  4. Send the payload to the application's message endpoint
  5. Verify that all records in the table were deleted despite the user not having permission to do so directly
  6. Create another payload to call the `get_data` method to extract sensitive information:
     ```json
     {
       "data": {},
       "checksum": "<valid_checksum>",
       "id": "<component_id>",
       "epoch": 123456789,
       "actionQueue": [
         {
           "type": "callMethod",
           "payload": {"name": "get_data(data_key='sensitive_data')"}
         }
       ]
     }
     ```
  7. Verify that sensitive information is returned in the response
