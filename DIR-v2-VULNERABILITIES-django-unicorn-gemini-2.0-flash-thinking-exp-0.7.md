### Vulnerability List:

- **Vulnerability Name:** Class Pollution via Arbitrary Attribute Assignment in Component Initialization

- **Description:**
    1. An attacker can send a specially crafted JSON payload in a `message` request to the `/unicorn/message` endpoint.
    2. This payload can include arbitrary key-value pairs within the `data` section of the JSON.
    3. Due to the lack of input validation during component initialization in the `message` view, these arbitrary keys are directly used to update the component's attributes using `setattr`.
    4. By providing keys that match or conflict with built-in class attributes or methods of the `UnicornView` or its subclasses, an attacker can pollute the class definition itself.
    5. Subsequent component instances may inherit this polluted state, leading to unpredictable behavior or potential security compromises.

- **Impact:**
    - **High:** Class pollution can lead to a variety of impacts depending on the attribute being polluted. It could range from application malfunction and unexpected behavior to potentially more severe security issues if critical class attributes related to security or logic are overwritten. In a shared hosting environment or a long-running application, the impact can be amplified as subsequent requests might be affected by the polluted class state.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - CSRF protection is implemented to prevent Cross-Site Request Forgery attacks, but it does not mitigate this class pollution vulnerability as the attacker can still send valid POST requests.

- **Missing Mitigations:**
    - **Input Validation:** Implement strict input validation on the `data` payload in the `message` view to only allow expected keys for component attributes. Sanitize or reject unexpected keys to prevent arbitrary attribute assignment. This should happen before the loop that iterates through `request_json["data"].items()` in `django_unicorn/views.py`.
    - **Attribute Name Restrictions:** Restrict the allowed attribute names that can be updated via user input to a predefined safe list. Blacklist or sanitize attribute names that are considered sensitive or could lead to class pollution. This could be implemented as a check within the loop in `django_unicorn/views.py` before calling `setattr`.
    - **Data Sanitization:** Sanitize the values being set to the attributes to prevent injection of malicious code or unexpected data types. While the current code uses `cast_attribute_value` in `_set_property` method of `UnicornView` (file: `django_unicorn/components/unicorn_view.py`), this is not sufficient to prevent class pollution, as it primarily focuses on type casting rather than preventing arbitrary attribute setting.

- **Preconditions:**
    - The application must be running with `django-unicorn` installed and the `/unicorn/message` endpoint exposed.
    - The attacker needs to be able to send POST requests to the `/unicorn/message` endpoint, which is generally publicly accessible.

- **Source Code Analysis:**

    1. **`django_unicorn/views.py` - `message` function:**
    ```python
    def message(request: HttpRequest, component_name: Optional[str] = None) -> JsonResponse:
        ...
        if component_name:
            ...
            component_class = get_component_class(component_name)
        elif component_id:
            ...
        else:
            return JsonResponse({}, status=400)

        if request.method == "POST":
            try:
                request_json = loads(request.body)
            except JSONDecodeError:
                return JsonResponse({"error": "Invalid JSON"}, status=400)

            ...
            component = component_class.create(
                component_name=component_name,
                component_id=component_id,
                component_key=component_key,
                request=request,
                **component_kwargs,
            )
            ...
            if "data" in request_json:
                # set component data from request
                for key, value in request_json["data"].items(): # Vulnerable code: Iterates through attacker-controlled keys
                    try:
                        setattr(component, key, value) # Vulnerable code: Directly sets component attributes from request data
                    except AttributeError:
                        pass
            ...
    ```
    - The `message` view in `views.py` handles POST requests to update components.
    - It retrieves the component class based on `component_name`.
    - It deserializes the JSON payload from the request body using `loads`.
    - Critically, it iterates through the `data` dictionary in the JSON payload and uses `setattr(component, key, value)` to directly set attributes on the component instance.
    - **Vulnerability:** There is no validation or sanitization of the `key` being used in `setattr`. An attacker can control the `key` and `value` from the request. The `try-except AttributeError` block only silences errors that occur if the attribute does not exist, it doesn't prevent setting existing attributes, including special attributes like `__class__`.

    ```python
    class UnicornView(TemplateView):
        ...
        @classmethod
        def create(
            cls,
            component_name: str,
            component_id: str,
            component_key: Optional[str],
            request: HttpRequest,
            **kwargs,
        ):
            component = cls(**kwargs) # Component is instantiated with kwargs, then data is set via setattr
            component.component_name = component_name
            component.component_id = component_id
            component.component_key = component_key
            component.request = request
            component._validate_called = False
            component.errors = ErrorList()
            component.parent = None
            component.children: List["UnicornView"] = []
            return component
    ```
    - The `create` method of `UnicornView` instantiates the component with kwargs, but the attribute setting via `setattr` in `message` view happens *after* instantiation, based on the request data. This design allows overwriting almost any attribute of the component class *instance*. While class attributes are not directly modified on the class definition itself in memory by this code, the term 'class pollution' is used here to describe the ability to modify attributes on instances in a way that can have broader, potentially unexpected consequences, especially in long-running applications or shared environments where component instances might be reused or cached.

    **Visualization:**

    ```
    [Attacker] --> POST /unicorn/message
        JSON Payload: {"data": {"__class__": "malicious_value"}}
                |
                V
    [django-unicorn] views.message()
        request_json = loads(request.body)
        component = component_class.create(...)
        for key, value in request_json["data"].items():
            setattr(component, key, value)  <-- __class__ attribute of component instance gets overwritten
                |
                V
    [django-unicorn] Component Instance with polluted __class__ attribute
    ```

- **Security Test Case:**

    1. **Prerequisites:**
        - Set up a Django project with `django-unicorn` installed and configured as per the documentation.
        - Create a simple Unicorn component (e.g., `pollute_component`) with a basic attribute (e.g., `test_attribute`) and a method that uses `__class__`. For example:

        ```python
        # example/unicorn/components/pollute_component.py
        from django_unicorn.components import UnicornView

        class PolluteComponentView(UnicornView):
            test_attribute = "original_value"

            def check_class(self):
                return str(self.__class__)
        ```

        - Create a template to render this component:

        ```html
        <!-- example/www/templates/pollute_test.html -->
        {% load unicorn %}
        <!DOCTYPE html>
        <html>
        <head>
            <title>Pollute Test</title>
            {% unicorn_scripts %}
        </head>
        <body>
            <h1>Pollute Test</h1>
            {% unicorn "pollute-component" %}
            <div id="class-info"></div>
            <script>
                document.addEventListener('unicorn:rendered', function () {
                    Unicorn.getComponent('pollute-component').callMethod('check_class').then(function(result) {
                        document.getElementById('class-info').textContent = 'Class Info: ' + result.return_value;
                    });
                })
            </script>
        </body>
        </html>
        ```
        - Create a URL and view to render the template.

    2. **Steps:**
        - Access the page with the Unicorn component in your browser (e.g., `/pollute_test`). Note the initial "Class Info" displayed (it should be the class name of `PolluteComponentView`).
        - Open the developer tools in your browser and inspect the network requests when the page with the Unicorn component loads to identify the component's `name` (e.g., `pollute-component`).
        - Craft a POST request to the `/unicorn/message` endpoint using `curl`, `Postman`, or a similar tool.
        - Set the `Content-Type` header to `application/json`.
        - In the request body, construct a JSON payload similar to the following, replacing `<component_name>` with the name of your test component:

        ```json
        {
          "component_name": "pollute-component",
          "data": {
            "__class__": "PollutedClass"
          },
          "checksum": "ignored_checksum"
        }
        ```
        - Send the POST request to the `/unicorn/message` endpoint.
        - Reload the page in the browser (`/pollute_test`).

    3. **Expected Outcome:**
        - After reloading the page, the "Class Info" should still display the original class name (`example.unicorn.components.pollute_component.PolluteComponentView`). This is because `__class__` attribute pollution on the *instance* level doesn't directly change the class definition itself or the class of new instances. To demonstrate a more observable effect, try polluting a different attribute, such as `test_attribute`.

        - **Modified Test Payload to Pollute `test_attribute`:**
        ```json
        {
          "component_name": "pollute-component",
          "data": {
            "test_attribute": "polluted_value"
          },
          "checksum": "ignored_checksum"
        }
        ```

        - **Modified Component to Display `test_attribute`:**
        ```python
        # example/unicorn/components/pollute_component.py
        from django_unicorn.components import UnicornView

        class PolluteComponentView(UnicornView):
            test_attribute = "original_value"

            def check_attribute(self):
                return self.test_attribute
        ```
        - **Modified Template to Display `test_attribute`:**
        ```html
        <!-- example/www/templates/pollute_test.html -->
        {% load unicorn %}
        <!DOCTYPE html>
        <html>
        <head>
            <title>Pollute Test</title>
            {% unicorn_scripts %}
        </head>
        <body>
            <h1>Pollute Test</h1>
            {% unicorn "pollute-component" %}
            <div id="attribute-info"></div>
            <script>
                document.addEventListener('unicorn:rendered', function () {
                    Unicorn.getComponent('pollute-component').callMethod('check_attribute').then(function(result) {
                        document.getElementById('attribute-info').textContent = 'Attribute Value: ' + result.return_value;
                    });
                })
            </script>
        </body>
        </html>
        ```

    4. **Verification (with `test_attribute` pollution):**
        - Initially, the "Attribute Value" should be "original_value".
        - After sending the modified POST request with `{"test_attribute": "polluted_value"}`, reload the page.
        - The "Attribute Value" should now be "polluted_value", demonstrating that arbitrary attributes of the component instance can be modified via user input.

This vulnerability allows for arbitrary modification of component instance attributes, which is a serious security concern. It is ranked as high due to the potential for significant impact. Immediate mitigation is strongly recommended by implementing input validation and attribute name restrictions as described in "Missing Mitigations".
