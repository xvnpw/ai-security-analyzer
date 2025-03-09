## Vulnerability List for django-unicorn Project

* Vulnerability Name: Cross-Site Scripting (XSS) via call Javascript function

* Description:
    1. An attacker can inject arbitrary Javascript code by manipulating the arguments passed to the `call` function in a component's view.
    2. When a component calls a Javascript function using `self.call("functionName", argument)`, the arguments are not properly sanitized before being passed to the client-side Javascript.
    3. An attacker can provide malicious input as `argument` that will be executed in the user's browser when the `call` function is invoked.

* Impact:
    - High
    - An attacker can execute arbitrary JavaScript code in the victim's browser, leading to potential data theft, session hijacking, defacement, or other malicious actions.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    - None. The project does not implement sanitization of arguments passed to the `call` function.

* Missing Mitigations:
    - Input sanitization: Arguments passed to the `call` function in the component's view should be properly sanitized on the server-side to remove or escape any potentially malicious JavaScript code before being passed to the client-side.
    - Contextual output encoding: Ensure that arguments are properly encoded in the JavaScript context on the client-side to prevent XSS.

* Preconditions:
    - The application uses the `call` function in a component's view to invoke client-side JavaScript functions and passes user-controlled input as arguments.

* Source Code Analysis:
    - In `django-unicorn\docs\source\javascript.md`, the documentation for "Call JavaScript from View" shows an example of using `self.call("hello", self.name)`.
    - The `name` variable in the example is directly passed to the Javascript `hello` function without any sanitization.
    - If the `name` variable is influenced by user input and not properly validated or sanitized, an attacker can inject malicious JavaScript code.
    - Step-by-step vulnerability trigger in code:
        1. User input is passed to a component's property (e.g., `name` in `CallJavascriptView`).
        2. The component's view calls `self.call("hello", self.name)` where `self.name` contains the user input.
        3. Django Unicorn serializes the `self.name` and sends it to the client-side.
        4. Client-side JavaScript executes `hello(argument)` where `argument` is the unsanitized user input.
        5. If the user input contains malicious JavaScript, it will be executed in the user's browser.

* Security Test Case:
    1. Create a Django Unicorn component with a view function that calls a Javascript function using `self.call()` and passes user-controlled input as an argument.
    ```python
    # malicious_call_javascript.py
    from django_unicorn.components import UnicornView

    class MaliciousCallJavascriptView(UnicornView):
        name = ""

        def hello(self):
            self.call("hello", self.name)
    ```
    2. Create a corresponding template:
    ```html
    <!-- malicious_call_javascript.html -->
    <div>
      <script>
        function hello(name) {
          // Vulnerable function that directly executes the argument
          eval(name);
        }
      </script>

      <input type="text" unicorn:model="name" />
      <button type="submit" unicorn:click="hello">Hello!</button>
    </div>
    ```
    3. Render the component in a Django template.
    4. In the input field, enter malicious Javascript code, for example: `<img src=x onerror=alert('XSS')>` or `alert('XSS')`.
    5. Click the "Hello!" button.
    6. Observe that the Javascript code is executed, demonstrating the XSS vulnerability. An alert box with 'XSS' should appear.

* Security Test Case:
    1. Setup a Django project with django-unicorn installed.
    2. Create a unicorn component named `xss_test` in `unicorn/components/xss_test.py`:
    ```python
    from django_unicorn.components import UnicornView

    class XssTestView(UnicornView):
        malicious_input = ""

        def trigger_js_call(self):
            self.call("showAlert", self.malicious_input)

    ```
    3. Create a template for the component in `unicorn/templates/unicorn/xss_test.html`:
    ```html
    <div>
        <script>
            function showAlert(input) {
                eval(input);
            }
        </script>
        <input type="text" unicorn:model="malicious_input">
        <button unicorn:click="trigger_js_call">Trigger XSS</button>
    </div>
    ```
    4. Include the component in a Django view and template.
    5. Access the page in a browser.
    6. In the input field, enter: `alert('XSS_VULNERABILITY')`
    7. Click "Trigger XSS".
    8. Observe an alert box appears with the message 'XSS_VULNERABILITY', confirming the vulnerability.
