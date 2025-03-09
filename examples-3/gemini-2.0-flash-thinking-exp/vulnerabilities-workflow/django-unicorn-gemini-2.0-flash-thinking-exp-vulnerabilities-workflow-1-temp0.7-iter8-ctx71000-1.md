## Vulnerability List

### Vulnerability Name: Insecure Method Invocation

* Description:
    1. An attacker can craft a malicious request to the Django Unicorn backend.
    2. This request can specify an arbitrary method name to be invoked on the `UnicornView` instance.
    3. The `django-unicorn` framework, without sufficient validation, uses `getattr` to retrieve and execute the method specified in the request payload.
    4. By manipulating the method name in the request, an attacker can potentially invoke any public method of the `UnicornView` class, regardless of the developer's intended actions.
    5. This can lead to unintended functionality execution, data manipulation, or information disclosure depending on the available methods in the `UnicornView` and the application logic.

* Impact:
    - **High**: An attacker can invoke arbitrary methods on the backend component. This can bypass intended application logic, potentially leading to data modification, unauthorized actions, or information disclosure. The exact impact depends on the specific methods available in the `UnicornView` and how they are implemented. In the worst case, if a `UnicornView` has methods that interact with sensitive data or perform critical operations without proper authorization checks, this vulnerability could be critical.
* Vulnerability Rank: high
* Currently Implemented Mitigations:
    - None. The code directly uses `getattr` with the method name provided from the client-side request without any explicit validation or sanitization of the method name against a whitelist of allowed methods.
* Missing Mitigations:
    - **Whitelist of allowed methods:** Implement a strict whitelist of methods that can be invoked from the frontend. The framework should only allow execution of methods explicitly defined as safe and intended to be called from the client side.
    - **Input validation and sanitization:** Validate and sanitize the method name received from the client to ensure it conforms to expected patterns and does not contain malicious characters or payloads.
* Preconditions:
    - The application must be using Django Unicorn framework.
    - The application must have `UnicornView` components with public methods that are not intended to be invoked directly by external users.
    - The attacker needs to be able to send AJAX requests to the Django Unicorn endpoint.
* Source Code Analysis:
    1. **File:** `django_unicorn/views.py`
    2. **Method:** `handle_action(self, request)`
    3. **Code Snippet:**
    ```python
    def handle_action(self, request):
        ...
        action_name = data.get("action_name")
        ...
        method, args, kwargs = parse_call_method_name(action_name)
        ...
        try:
            if hasattr(self, method):
                component_method = getattr(self, method) # Vulnerable line
                ...
                return_value = component_method(*args, **kwargs)
        ...
    ```
    4. **Vulnerability Flow:**
        - The `handle_action` method retrieves the `action_name` from the request `data`. This `action_name` is directly controlled by the client.
        - `parse_call_method_name` parses the `action_name` string to extract the method name, arguments, and keyword arguments.
        - `getattr(self, method)` retrieves a method from the `UnicornView` instance using the `method` name parsed from the client request. **This is the vulnerable point.** There is no check to ensure that the `method` is a safe or intended method to be called from the frontend.
        - `component_method(*args, **kwargs)` then executes the retrieved method.
    5. **Visualization:**
    ```
    Client Request (action_name: "malicious_method") --> handle_action()
                                                                |
                                        parse_call_method_name() --> method = "malicious_method"
                                                                |
                                                getattr(self, method) --> Retrieves self.malicious_method (if exists)
                                                                |
                                        component_method(*args, **kwargs) --> Executes self.malicious_method()
    ```

* Security Test Case:
    1. **Pre-requisite:** Set up a Django project with django-unicorn installed and a simple Unicorn component with at least two methods: one intended to be called from the template (e.g., `increment_count`) and another one that is not intended to be directly accessible from the template, but is still public (e.g., `delete_all_users` - for demonstration purposes, this method should ideally not actually delete users in a real test, but rather perform a harmless action to prove method invocation).
    2. **Component Code Example (`test_component.py`):**
    ```python
    from django_unicorn.components import UnicornView

    class TestComponentView(UnicornView):
        count = 0

        def increment_count(self):
            self.count += 1

        def unsafe_method(self):
            self.count = 999 # Harmless action for demonstration, in real scenario could be dangerous
    ```
    3. **Template Code Example (`test_component.html`):**
    ```html
    {% load unicorn %}
    <div>
        Count: {{ count }}
        <button unicorn:click="increment_count">Increment</button>
    </div>
    ```
    4. **Test Steps:**
        a. Render the template containing the `test_component`. Observe the initial count value (0).
        b. Click the "Increment" button. Verify that `increment_count` method is correctly called and the count increases.
        c. Open browser's developer tools and inspect the AJAX request sent when clicking "Increment" button. Note the structure of the request payload, particularly the `"action_name"` parameter.
        d. Manually craft a new AJAX POST request to the Django Unicorn endpoint (`/unicorn/message/test-component`) using tools like `curl`, `Postman` or browser's developer console.
        e. In the crafted request payload, modify the `"action_name"` parameter to call the unintended method, e.g., `"action_name": "unsafe_method"`. Keep other necessary parameters like `component_id`, `checksum`, and `data` consistent with a valid request.
        f. Send the crafted request.
        g. After sending the request, re-render or refresh the component (e.g., by clicking "Increment" again or refreshing the page).
        h. **Verification:** Observe the `count` value. If the `unsafe_method` was successfully invoked, the count value should be changed to 999 (or whatever action `unsafe_method` performs). This confirms the Insecure Method Invocation vulnerability.

* Missing Mitigations:
    - Input validation and sanitization for `action_name`.
    - Implementation of a whitelist for allowed methods.

This vulnerability allows an attacker to bypass the intended interaction flow of the component and directly trigger backend methods, potentially leading to significant security risks. It is crucial to implement mitigations, especially a method whitelist, to restrict the callable methods to only those explicitly intended for frontend interaction.
