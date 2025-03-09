- Vulnerability Name: Logic Manipulation via Unsafe Data Handling in `eval_value` and `set_property_from_data`
  - Description:
    1. A threat actor can craft malicious payloads in `call_method_name` requests (for method calls) or in data sent to update component properties.
    2. For method calls, the `django-unicorn` backend receives the payload and calls `parse_call_method_name` function in `django_unicorn\django_unicorn\call_method_parser.py`. For property updates, the `django-unicorn` backend receives the update data and calls `set_property_from_data` function in `django_unicorn\django_unicorn\views\utils.py`.
    3. `parse_call_method_name` uses `ast.parse` and `eval_value`. `eval_value` uses `ast.literal_eval` to parse string arguments into Python literals. `set_property_from_data` attempts to set component properties based on provided data, including deserializing data into Django models and querysets.
    4. **Vulnerability:** While `ast.literal_eval` (in `eval_value`) and the data handling in `set_property_from_data` prevent direct execution of arbitrary Python code, they can still lead to vulnerabilities through type coercion and manipulation of application logic. Both mechanisms parse user-provided strings into Python data structures. If component methods (for method calls) or component property handling logic (for property updates) do not explicitly validate the *type* and *structure* of these parsed arguments and rely on implicit type coercion, attackers can supply unexpected data structures (like nested dictionaries or lists) that, when processed by the component's backend logic, might cause unintended behavior. This is especially concerning if these coerced values are used in operations that assume specific data types or are involved in security-sensitive logic within the component. For example, a component might expect a string representing a filename but receive a list, leading to incorrect file operations or bypasses of intended security checks if not properly validated. This risk extends to `set_property_from_data` when updating model or queryset properties. If the data provided to `set_property_from_data` is not strictly validated against the expected model structure or queryset filters, attackers could potentially manipulate model data in unintended ways.
    5. If a threat actor can manipulate arguments passed to component methods (via `call_method_name`) or data used to update component properties, and if the component methods or property setters don't properly validate or sanitize both the *type* and *content* of these inputs, it could lead to unintended actions, data manipulation, or logic bypasses. The risk is heightened in scenarios where component logic naively uses values from `eval_value` or `set_property_from_data` without type and structure validation.
  - Impact:
    - Although direct remote code execution is unlikely due to the usage of `ast.literal_eval` and the design of property updates, a threat actor might be able to manipulate application logic by providing unexpected data types or values through method arguments or property update data. This can lead to data corruption, unintended actions, or potentially bypassing application-level security checks, depending on how the arguments and properties are used within the component's backend logic. The severity depends on how critical the component's actions are and how robust the input validation is within the component's methods and property handling logic. If component logic naively uses values without type and structure validation, the impact could be high, potentially allowing for unintended data access or modification, or execution of component logic in ways not originally intended.
  - Vulnerability Rank: High
  - Currently Implemented Mitigations:
    - The project uses `ast.literal_eval` instead of `eval` in `eval_value`, which restricts the evaluation to literal Python expressions, reducing the risk of arbitrary code execution in method arguments.
    - Type hints are used in component methods and properties, which might provide some level of input validation if type coercion is enforced correctly *by the developer in their component logic*. However, django-unicorn itself does not enforce type hints at runtime for security purposes; it's up to the component developer to utilize type hints for validation in their method and property implementations.
    - The documentation encourages developers to use Django forms for validation, which can help mitigate vulnerabilities arising from untrusted user input. This is a best practice recommendation, but not a built-in mitigation in `django-unicorn` itself.
  - Missing Mitigations:
    - Lack of explicit, *enforced* input validation and sanitization within `django-unicorn`'s core `parse_call_method_name`, `eval_value`, and `set_property_from_data` functions. While `ast.literal_eval` provides a degree of safety against direct code injection in method arguments, it and the data handling in `set_property_from_data` do not prevent logic manipulation via type coercion and unexpected data structures in both method arguments and property updates. More robust validation should be implemented *in user components* to ensure that the parsed arguments and property update data are safe and of the expected type and structure before being used in component methods and property setters.  `django-unicorn` could potentially provide utilities or guidelines to encourage or simplify this process for developers.
    - Lack of clear and prominent guidance in the documentation, beyond the general recommendation to use Django forms, specifically on how to properly validate and sanitize method arguments *within component methods* and property update data handling to prevent potential issues arising from argument and data manipulation. The documentation should emphasize the need to validate not just the content but also the *type* and *structure* of arguments parsed by `eval_value` and data processed by `set_property_from_data`, especially when dealing with complex data structures and when updating models or querysets.
  - Preconditions:
    - The application uses `django-unicorn` components that handle user-provided input through actions, methods, and property updates.
    - Component methods and property handling logic rely on the type coercion performed by `eval_value` or implicit data handling in `set_property_from_data` and do not implement sufficient input validation to check for expected types and data structures beyond basic type hints.
    - An attacker needs to be able to send crafted requests to the `django-unicorn` endpoint to trigger component actions with malicious arguments or property updates with malicious data.
  - Source Code Analysis:
    - File: `django_unicorn\django_unicorn\call_method_parser.py`
    ```python
    @lru_cache(maxsize=128, typed=True)
    def eval_value(value):
        """
        Uses `ast.literal_eval` to parse strings into an appropriate Python primitive.
        ...
        """
        try:
            value = ast.literal_eval(value) # Potential vulnerability: relies on ast.literal_eval for parsing
        except SyntaxError:
            value = _cast_value(value)
        return value


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
        tree = ast.parse(method_name, "eval") # Uses ast.parse
        statement = tree.body[0].value #type: ignore

        if tree.body and isinstance(statement, ast.Call):
            call = tree.body[0].value # type: ignore
            method_name = call.func.id
            args = [eval_value(arg) for arg in call.args] # Calls eval_value for each argument
            kwargs = {kw.arg: eval_value(kw.value) for kw.value in call.keywords} # Calls eval_value for each keyword argument
        ...
    ```
    - File: `django_unicorn\django_unicorn\views\utils.py`
    ```python
    def set_property_from_data(component: UnicornView, name: str, value: Any):
        """
        Set property for component.
        """
        # ... (Type hint handling and property setting logic)
        if isinstance(field_type, Model):
            if isinstance(value, dict):
                model_class = field_type
                model = _construct_model(model_class, value) # Potential vulnerability: Unsafe model construction from dict
                setattr(component, name, model)
        elif isinstance(field_type, QuerySetType):
            if isinstance(value, list):
                model_class = field_type.args[0]  # type: ignore
                queryset = model_class.objects.none()

                for item in value: # Iterates through list of dicts
                    if isinstance(item, dict):
                        model = _construct_model(model_class, item) # Potential vulnerability: Unsafe model construction from dict in list
                        queryset |= model_class.objects.filter(pk=model.pk) # Assumes pk exists in model
                setattr(component, name, queryset)
        # ... (other type handling)
    ```
    - File: `django_unicorn\django_unicorn\typer.py`
    ```python
    def _construct_model(model_class: Type[Model], model_data: Dict) -> Type[Model]:
        """
        Constructs a model instance from model_data.
        """
        # ... (Model construction logic using model_data dict)
        instance = model_class(**init_kwargs) # Potential vulnerability: Model instantiation with dict from user input
        # ... (Handling foreign keys and many-to-many relationships)
        return instance
    ```
    - Visualization (Method Call Argument Parsing):
      ```mermaid
      graph LR
          A[Request Payload (call_method_name)] --> B(parse_call_method_name);
          B --> C{ast.parse};
          C --> D{eval_value (arg 1)};
          C --> E{eval_value (arg 2)};
          C --> F{eval_value (kwarg 1)};
          D --> G[Component Method Call];
          E --> G;
          F --> G;
          G --> H[Application Logic & Potential Vulnerability if no validation on arg type/structure];
      ```
    - Visualization (Property Update Data Handling):
      ```mermaid
      graph LR
          A[Request Payload (property update data)] --> B(set_property_from_data);
          B --> C{_construct_model (if Model/QuerySet)};
          C --> D[Model Instantiation with user-provided dict];
          D --> E[Component Property Update];
          E --> F[Application Logic & Potential Vulnerability if no validation on data type/structure];
      ```
  - Security Test Case:
    1. **Setup:** Create a Django Unicorn component with a method and a model property that are vulnerable to data manipulation through unexpected data structures.
       ```python
       # components/vulnerable_component.py
       from django_unicorn.components import UnicornView
       from example.coffee.models import Flavor

       class VulnerableComponent(UnicornView):
           message = ""
           flavor_property: Flavor = None

           def mount(self):
               self.flavor_property = Flavor(name="Initial Flavor")
               self.flavor_property.save()

           def process_data(self, data):
               if 'name' in data and isinstance(data['name'], str):
                   self.message = f"Hello, {data['name']}!"
               else:
                   self.message = "Invalid data format."

           def update_flavor(self, flavor_data):
               if isinstance(flavor_data, dict) and 'name' in flavor_data:
                   self.flavor_property.name = flavor_data['name']
                   self.flavor_property.save()
                   self.message = f"Flavor updated to {self.flavor_property.name}"
               else:
                   self.message = "Invalid flavor data."

       ```
       Template:
       ```html
       {# templates/unicorn/vulnerable-component.html #}
       <div>
           <p>Flavor Name: {{ flavor_property.name }}</p>
           <p>Message: {{ message }}</p>

           <button unicorn:click="process_data({'name': 'World'})">Process Data (Method Call)</button>
           <input unicorn:model.lazy="methodInput" type="text" placeholder="Enter data for method as Python dict string"/>
           <button unicorn:click="process_data(methodInput)">Process User Method Input</button>

           <button unicorn:click="update_flavor({'name': 'New Flavor'})">Update Flavor (Property Update)</button>
           <input unicorn:model.lazy="propertyInput" type="text" placeholder="Enter data for property as Python dict string"/>
           <button unicorn:click="update_flavor(propertyInput)">Update Flavor with User Property Input</button>
       </div>
       ```

    2. **Initial Test (Normal Cases):** Render the component and test the default buttons and inputs. Verify that "Process Data (Method Call)" and "Update Flavor (Property Update)" work as expected. Verify that user input for both method and property updates works as expected with valid dictionary strings.

    3. **Malicious Payload Crafting (Method Call):** Using browser developer tools, intercept the AJAX request for "Process User Method Input". Modify `call_method_name` to inject a list instead of a dictionary, e.g., `process_data(['malicious', 'list', 'input'])`. Send the request. Observe if the component displays "Invalid data format." or exhibits errors due to unexpected input type in `process_data`.

    4. **Malicious Payload Crafting (Property Update):** Using browser developer tools, intercept the AJAX request for "Update Flavor with User Property Input". Modify the property update data (within the `data` payload) to inject a list instead of a dictionary for `flavor_property`, or inject a dictionary with unexpected structure. For example, try sending `{"flavor_property": ['malicious', 'list']}` or `{"flavor_property": {'unexpected_key': 'malicious'}}`. Send the request. Observe the server response and component behavior. Check if `flavor_property.name` is updated in an unexpected way, if errors occur, or if "Invalid flavor data." message is shown (if you added such validation in `update_flavor`).

    5. **Success Condition:** If the component's behavior deviates from the intended logic when provided with manipulated data in either method calls or property updates (e.g., displays "Invalid data format." when it shouldn't for valid input, throws exceptions, or updates data in unexpected ways due to type coercion or incorrect data structure assumptions), it indicates a vulnerability.  Specifically, demonstrate that providing a list to `process_data` or malformed data for `flavor_property` can lead to unintended behavior because of insufficient validation in the component's methods and property handling logic after `eval_value` or `set_property_from_data` processing. Success would be showing that argument or property data manipulation via crafted payloads can cause unintended behavior because of insufficient validation in the component logic.
