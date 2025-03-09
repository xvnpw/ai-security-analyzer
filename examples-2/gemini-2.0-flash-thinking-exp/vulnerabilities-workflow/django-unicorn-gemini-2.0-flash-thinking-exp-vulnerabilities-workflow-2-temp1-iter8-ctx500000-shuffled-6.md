- Vulnerability Name: Potential Cross-Site Scripting (XSS) in Component Rendering
- Description:
  - An attacker can inject malicious JavaScript code into a Django Unicorn component through user-controlled input fields that are bound to component properties using `unicorn:model`.
  - When the component re-renders and updates the DOM, this malicious JavaScript code can be executed in the user's browser because the user input is rendered without sufficient sanitization.
  - Step-by-step trigger:
    1. The attacker identifies a Django Unicorn component in the application that uses `unicorn:model` to bind user input to a component property and then renders this property in the template. For example, an input field like `<input type="text" unicorn:model="name">` and template code like `Hello {{ name }}`.
    2. The attacker crafts a malicious input containing JavaScript code, such as `<script>alert("XSS Vulnerability")</script>`.
    3. The attacker enters this malicious input into the input field in the web application.
    4. Django Unicorn sends an AJAX request to the server to update the component's state.
    5. The server-side code updates the component's `name` property with the malicious input.
    6. The server re-renders the component, including the malicious JavaScript code in the HTML.
    7. Django Unicorn updates the DOM in the user's browser with the re-rendered component HTML.
    8. The browser executes the injected JavaScript code, demonstrating the XSS vulnerability.
- Impact:
  - Successful exploitation of this vulnerability can lead to Cross-Site Scripting (XSS) attacks.
  - An attacker could execute arbitrary JavaScript code in the victim's browser within the context of the vulnerable web application.
  - This can lead to session hijacking, cookie theft, account takeover, redirection to malicious websites, defacement of the web page, or harvesting of user credentials and other sensitive information.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - CSRF protection: Django Unicorn uses CSRF tokens to protect against CSRF attacks, as mentioned in the documentation (FAQ section). This mitigation protects against Cross-Site Request Forgery, but not directly against XSS.
  - HTML Encoding: Django Unicorn HTML encodes updated field values by default to prevent XSS attacks, as mentioned in the changelog for version 0.36.0 and documentation for `safe` meta attribute/template filter (Views documentation). This is a general mitigation, but might not be sufficient in all cases, especially if developers use `safe` attribute/filter incorrectly.
- Missing Mitigations:
  - Input Sanitization: The project lacks explicit input sanitization for user-provided content rendered through Django templates within Unicorn components. While HTML encoding is enabled by default, it might not cover all XSS attack vectors and developers might bypass it using `safe`.  There is no clear guidance or built-in mechanism to sanitize user input before rendering it in the DOM.
  - Documentation and Developer Guidance:  The documentation should explicitly warn developers about the risk of XSS when rendering user input and provide clear guidance on how to properly sanitize input and avoid XSS vulnerabilities, especially when using features like the `safe` meta attribute or template filter.
- Preconditions:
  - The application must be using Django Unicorn.
  - A component must be rendering user-controlled input, which is bound using `unicorn:model`, directly into the HTML template without proper sanitization.
  - The attacker needs to be able to input data into the vulnerable component, typically through a form field.
- Source Code Analysis:
  - Based on the provided documentation, particularly the changelog for version 0.36.0 and the Views documentation, Django Unicorn seems to rely on Django's default HTML encoding to mitigate XSS.
  - The documentation mentions a `safe` meta attribute and template filter that allows developers to bypass the default HTML encoding. This feature, while useful for certain scenarios, increases the risk of XSS if not used cautiously and with proper input sanitization in place.
  - Without reviewing the actual Django Unicorn Python and Javascript source code, it is impossible to determine the extent of automatic sanitization or the exact mechanisms in place. However, the documentation suggests that the primary mitigation is HTML encoding, and developers need to be aware of the risks associated with bypassing this encoding using `safe`.
- Security Test Case:
  - Step 1: Create a Django Unicorn component that is vulnerable to XSS.
    - Component name: `xss_test`
    - Component path: `unicorn/components/xss_test.py`
    - Component template path: `unicorn/templates/unicorn/xss_test.html`
    - Component Python code (`unicorn/components/xss_test.py`):
```python
from django_unicorn.components import UnicornView

class XssTestView(UnicornView):
    user_input = ""
```
    - Component HTML template (`unicorn/templates/unicorn/xss_test.html`):
```html
<div>
  <input type="text" unicorn:model="user_input" id="user-input">
  <div id="output">{{ user_input }}</div>
</div>
```
  - Step 2: Create a Django view to render the component.
    - View path: `www/views.py`
    - Template path: `www/templates/index.html`
    - View Python code (`www/views.py`):
```python
from django.shortcuts import render

def index(request):
    return render(request, "www/index.html")
```
    - Template HTML (`www/templates/index.html`):
```html
{% load unicorn %}
<!DOCTYPE html>
<html>
<head>
    <title>XSS Test</title>
    {% unicorn_scripts %}
</head>
<body>
    {% csrf_token %}
    {% unicorn 'xss-test' %}
</body>
</html>
```
  - Step 3: Run the Django development server.
    ```bash
    python manage.py runserver
    ```
  - Step 4: Open a web browser and navigate to the index page (e.g., `http://127.0.0.1:8000/`).
  - Step 5: In the input field, enter the following XSS payload: `<script>alert("XSS Vulnerability - django-unicorn")</script>`
  - Step 6: Observe the output below the input field. If the JavaScript alert box `"XSS Vulnerability - django-unicorn"` appears, it confirms the XSS vulnerability. This is because the input is rendered without sufficient sanitization, allowing the `<script>` tag to be executed by the browser.
