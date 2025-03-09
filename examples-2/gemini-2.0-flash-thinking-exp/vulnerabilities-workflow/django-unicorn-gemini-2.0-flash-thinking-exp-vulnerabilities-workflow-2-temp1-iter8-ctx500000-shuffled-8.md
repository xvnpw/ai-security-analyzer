### 1. Cross-Site Scripting (XSS) in Template Rendering

- Description:
  - Django-unicorn allows dynamic rendering of component templates based on data from the backend.
  - If a component's template directly renders user-provided data without proper sanitization, it can lead to Cross-Site Scripting (XSS) vulnerabilities.
  - An attacker can inject malicious JavaScript code through user input fields (e.g., text inputs bound with `unicorn:model`).
  - When the component re-renders with the attacker's input, the malicious JavaScript code gets executed in the victim's browser.
  - Steps to trigger vulnerability:
    1. Find an input field in a django-unicorn component template that uses `unicorn:model` to bind to a component property.
    2. Inject malicious JavaScript code as input into this field, for example: `<script>alert("XSS")</script>`.
    3. Trigger an action that causes the component to re-render (e.g., by clicking a button, submitting a form, or typing in another bound input field if using `unicorn:model.live`).
    4. If the component template directly renders the bound property without sanitization, the injected JavaScript code will be executed.

- Impact:
  - **High**
  - Successful XSS attacks can have severe consequences:
    - Account takeover: Attackers can steal session cookies or user credentials.
    - Data theft: Attackers can access sensitive user data or application data.
    - Website defacement: Attackers can modify the content of the web page seen by the user.
    - Redirection to malicious sites: Attackers can redirect users to phishing websites or malware distribution sites.

- Vulnerability Rank: **High**

- Currently Implemented Mitigations:
  - Django automatically applies HTML escaping to template variables, which is Django's primary built-in XSS mitigation.
  - The documentation mentions that "By default, `unicorn` HTML encodes updated field values to prevent XSS attacks." and "You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple." ([views.md](..\django-unicorn\docs\source\views.md))

- Missing Mitigations:
  - While Django's auto-escaping is active by default, developers need to be explicitly aware of situations where they might be bypassing it, such as:
    - Using the `safe` filter or `{% safetrans %}` template tag incorrectly on user-provided data.
    - Rendering user input as raw HTML using `|safe` filter or by setting `safe = ("something_safe", )` in component's `Meta` class without proper sanitization.
  - There isn't a clear and prominent warning in the documentation about the risks of bypassing auto-escaping and best practices for sanitizing user input, particularly within the context of django-unicorn components.

- Preconditions:
  - The application must be using django-unicorn.
  - A component template must render user-provided data dynamically using Django template language and the developer must bypass default auto-escaping, either by using `|safe` filter or `safe` Meta option.
  - An attacker needs to be able to control the user-provided data that is rendered in the template.

- Source Code Analysis:
  - In `django_unicorn/components/unicorn_template_response.py`, the `UnicornTemplateResponse.render` method is responsible for rendering the component. It uses `BeautifulSoup` to parse and update the DOM.
  - The documentation ([views.md](..\django-unicorn\docs\source\views.md)) indicates that HTML encoding is applied by default.
  - However, the `safe` Meta option and the `|safe` template filter allow developers to bypass this encoding. If these are used incorrectly on user-provided data, it opens the door to XSS.
  - Example from documentation showing how to bypass encoding:
    ```html
    <!-- safe-example.html -->
    <div>
      <input unicorn:model="something_safe" />
      {{ something_safe|safe }}
    </div>
    ```
    ```python
    # safe_example.py
    from django_unicorn.components import UnicornView

    class SafeExampleView(UnicornView):
        something_safe = ""

        class Meta:
            safe = ("something_safe", )
    ```
  - The code itself does not implement any input sanitization beyond Django's default template auto-escaping, and explicitly provides mechanisms for developers to disable it.

- Security Test Case:
  1. Create a django-unicorn component that renders a property bound to a text input using `unicorn:model` and uses the `|safe` filter to output this property in the template.
  2. Create a Django view that includes this component in a template.
  3. Access the view in a browser.
  4. In the input field, enter the following payload: `<img src=x onerror=alert('XSS')>`.
  5. Trigger a django-unicorn action that re-renders the component (e.g., click a button that updates another component property).
  6. Observe if the JavaScript alert `XSS` is executed. If it is, the vulnerability is confirmed.

```html
File: myapp/templates/unicorn/xss_component.html
```
```html
<div>
  <input type="text" unicorn:model="userInput">
  <div unicorn:id="output" >
    {{ userInput|safe }}
  </div>
  <button unicorn:click="$refresh">Refresh</button>
</div>
```
```python
File: myapp/components/xss_component.py
```
```python
from django_unicorn.components import UnicornView

class XssComponentView(UnicornView):
    userInput = ""
```
  7. Access the page containing this component. Input `<img src=x onerror=alert('XSS')>` in the text field and click "Refresh". An alert box with "XSS" will appear, confirming the vulnerability.

```html
File: myapp/templates/index.html
```
```html
{% load unicorn %}
<html>
<head>
    {% unicorn_scripts %}
</head>
<body>
    {% csrf_token %}
    {% unicorn 'xss-component' %}
</body>
</html>
```
```python
File: myapp/views.py
```
```python
from django.shortcuts import render
from django.http import HttpResponse

def index(request):
    return render(request, 'index.html')
```
```python
File: myapp/urls.py
```
```python
from django.urls import path
from .views import index

urlpatterns = [
    path('', index, name='index'),
]
```
```python
File: project/urls.py
```
```python
from django.contrib import admin
from django.urls import path, include
from myapp import urls as myapp_urls

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include(myapp_urls)),
    path("unicorn/", include("django_unicorn.urls")),
]
```
```python
File: project/settings.py (add to INSTALLED_APPS)
```
```python
INSTALLED_APPS = [
    ...
    'myapp',
    'django_unicorn',
    ...
]
```
This setup will demonstrate that by using `|safe` in the template, the injected JavaScript will execute.
