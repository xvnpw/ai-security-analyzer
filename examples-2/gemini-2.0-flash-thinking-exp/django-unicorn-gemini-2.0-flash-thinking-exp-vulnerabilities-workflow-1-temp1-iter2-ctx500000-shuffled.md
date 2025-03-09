### Cross-Site Scripting (XSS) vulnerability due to unsafe usage of `safe` attribute/filter

* Description:
    1. A threat actor identifies a Django Unicorn component that uses the `safe` attribute in the template, intending to render user-provided content without HTML encoding.
    2. The attacker crafts a malicious input containing JavaScript code, such as `<img src=x onerror=alert('XSS')>`.
    3. The attacker injects this malicious input into a form field that is bound to a component property using `unicorn:model`.
    4. The component re-renders, and due to the `safe` attribute or filter, the malicious JavaScript is included in the HTML output without proper encoding.
    5. When a user views the page, the malicious JavaScript executes in their browser, potentially leading to account takeover, data theft, or other malicious actions.

* Impact:
    - Execution of arbitrary JavaScript code in the victim's browser.
    - Potential for account takeover if session cookies are stolen.
    - Defacement of the website.
    - Redirection to malicious websites.
    - Data theft if sensitive information is accessible to the JavaScript code.

* Vulnerability rank: high

* Currently implemented mitigations:
    - By default, django-unicorn HTML encodes updated field values to prevent XSS attacks.
    - Documentation warns against putting sensitive data into public properties and highlights the risks of using the `safe` attribute, advising caution and explicit opt-in.
    - The changelog mentions security fixes related to XSS, indicating awareness and past efforts to mitigate such vulnerabilities.

* Missing mitigations:
    - Content Security Policy (CSP) headers are not automatically set by django-unicorn. CSP could provide an additional layer of defense by restricting the sources from which the browser is permitted to load resources, and help prevent execution of injected JavaScript even if `safe` is misused.
    - No automated checks or warnings in the project to detect potentially unsafe uses of the `safe` attribute or filter.

* Preconditions:
    - A Django Unicorn component exists that uses either `Meta.safe` or the `safe` template filter to render user-controlled data without sufficient sanitization.
    - An attacker can influence the data rendered by this component, typically through `unicorn:model` bindings.

* Source code analysis:
    1. **`..\django-unicorn\docs\source\views.md`**: This documentation file describes the `safe` meta attribute and the `javascript_exclude` attribute within the `Meta` class of `UnicornView`. It explicitly warns against putting sensitive data into public properties and explains that by default, `unicorn` HTML encodes updated field values to prevent XSS attacks. It also details how to use `safe` to opt-out of encoding.

    2. **`..\django-unicorn\docs\source\safe-example.md`**: This documentation provides an example of using the `safe` meta attribute.

    3. **`..\django-unicorn\docs\source\templates.md`**: This documentation mentions "Django HTML templates, so anything you could normally do in a Django template will still work, including template tags, filters, loops, if statements, etc." implying that Django's template `safe` filter is also usable and could lead to similar vulnerabilities if misused.

    4. **`..\django-unicorn\docs\source\changelog.md`**: Reviewing the changelog, specifically versions `0.36.0` and `0.36.1`, reveals that security fixes for XSS attacks have been implemented. Version `0.36.0` mentions "Security fix: for CVE-2021-42053 to prevent XSS attacks" and states "responses will be HTML encoded going forward (to explicitly opt-in to previous behavior use [safe](views.md#safe))". Version `0.36.1` mentions "More complete handling to prevent XSS attacks.". These entries confirm that XSS is a known concern and that the project implemented default HTML encoding as a mitigation, while providing `safe` as a way to bypass it, with the associated risks.

    5. **`..\django-unicorn\django_unicorn\utils.py`**: The `sanitize_html` function is defined here. This function is likely used to perform the default HTML encoding. However, it is important to note that the `safe` functionality, when used, would bypass this sanitization.

* Security test case:
    1. Create a Django Unicorn component that renders a property called `unsafe_content` in its template, using the `safe` filter or `Meta.safe`. For example, using `Meta.safe`:

    ```python
    # unsafe_xss_component.py
    from django_unicorn.components import UnicornView

    class UnsafeXSSView(UnicornView):
        unsafe_content = ""

        class Meta:
            safe = ("unsafe_content",)
    ```

    ```html
    <!-- unsafe-xss.html -->
    <div>
        {% load unicorn %}
        <input type="text" unicorn:model.defer="unsafe_content">
        <div id="content">
            {{ unsafe_content }}
        </div>
    </div>
    ```

    2. In a Django view, render this component.

    ```python
    # views.py
    from django.shortcuts import render
    from .components.unsafe_xss_component import UnsafeXSSView

    def unsafe_xss_view(request):
        return render(request, 'unsafe_xss_template.html', {'component_name': 'unsafe-xss'})
    ```

    ```html
    <!-- unsafe_xss_template.html -->
    {% load unicorn %}
    <!DOCTYPE html>
    <html>
    <head>
        <title>Unsafe XSS Test</title>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        {% unicorn component_name %}
    </body>
    </html>
    ```

    3. Access the page in a browser.
    4. In the input field, enter the following payload: `<img src=x onerror=alert('XSS-Unicorn')>`
    5. Click outside the input field to trigger `unicorn:model.defer` update.
    6. Observe if an alert box with "XSS-Unicorn" appears. If the alert appears, the XSS vulnerability is confirmed because the JavaScript code was executed.
    7. To test with the `safe` template filter, modify the component template like this: `{{ unsafe_content|safe }}` and repeat steps 4-6. The vulnerability should also be present.

    8. As a control test, remove the `safe` attribute from the Meta class (or remove the `|safe` filter from the template) and repeat steps 4-6. The alert should not appear, demonstrating that default encoding prevents the XSS and that the vulnerability is specifically related to the usage of `safe`.

### Cross-Site Scripting (XSS) vulnerability via call Javascript function

* Description:
    1. An attacker can inject arbitrary Javascript code by manipulating the arguments passed to the `call` function in a component's view.
    2. When a component calls a Javascript function using `self.call("functionName", argument)`, the arguments are not properly sanitized before being passed to the client-side Javascript.
    3. An attacker can provide malicious input as `argument` that will be executed in the user's browser when the `call` function is invoked.

* Impact:
    - High
    - An attacker can execute arbitrary JavaScript code in the victim's browser, leading to potential data theft, session hijacking, defacement, or other malicious actions.

* Vulnerability rank: high

* Currently implemented mitigations:
    - None. The project does not implement sanitization of arguments passed to the `call` function.

* Missing mitigations:
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
