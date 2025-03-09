- vulnerability name: Cross-Site Scripting (XSS) in component rendering
  - description: Django-unicorn renders components by sending HTML updates over AJAX. When a component is re-rendered, the HTML is merged into the existing DOM using morphdom. If a component's attribute value is updated with a malicious string containing JavaScript code and that attribute is rendered in the template without proper escaping, it can lead to XSS.
    Steps to trigger:
      1. Create a component with a string attribute that is rendered in the template without the `safe` filter or `Meta.safe`.
      2. In the component's Python code, create an action method that updates this string attribute with a malicious JavaScript payload.
      3. Create a template that includes this component and renders the attribute.
      4. Trigger the action method from the frontend, causing the attribute to be updated with the malicious payload.
      5. The component re-renders, and the malicious JavaScript is injected into the DOM and executed in the user's browser.
  - impact: Successful XSS attack can allow an attacker to:
      - Steal user session cookies, giving them access to the user's account.
      - Redirect the user to a malicious website.
      - Deface the website.
      - Perform actions on behalf of the user.
      - Inject malware.
  - vulnerability rank: high
  - currently implemented mitigations: HTML encoding by default: `django-unicorn` HTML encodes updated field values to prevent XSS attacks. This is mentioned in changelog for version 0.36.0 and in documentation for `views.md#safe`.
  - missing mitigations: While default HTML encoding is implemented, developers can explicitly bypass it using `safe` template filter or `Meta.safe`. If developers are not careful and use `safe` for user-controlled content, XSS vulnerability can be introduced. There is no mechanism to prevent developers from using `safe` incorrectly.
  - preconditions:
      - A django-unicorn application is deployed and publicly accessible.
      - A component exists that renders a string attribute without proper escaping (using `safe` filter or `Meta.safe`).
      - An action method in the component can be triggered by an attacker to update this string attribute with malicious content.
  - source code analysis:
      1. **django_unicorn\components\unicorn_view.py:** The `get_frontend_context_variables` method is responsible for preparing data to be sent to the frontend.
      2. **django_unicorn\serializer.py:** The `dumps` function in `serializer.py` is used to serialize the data to JSON. By default, it seems like `orjson.dumps` is used, which should handle basic JSON serialization but doesn't automatically perform HTML escaping.
      3. **django_unicorn\docs\source\views.md:** The documentation for `Meta.safe` indicates that by default, `unicorn` HTML encodes updated field values to prevent XSS attacks, but it allows opting out of encoding using `Meta.safe` or `safe` template filter.
      4. **django_unicorn\docs\source\changelog.md:** Changelog for version 0.36.0 mentions "Security fix: for CVE-2021-42053 to prevent XSS attacks (reported by [Jeffallan](https://github.com/Jeffallan)). responses will be HTML encoded going forward (to explicitly opt-in to previous behavior use [safe](views.md#safe))". This confirms that HTML encoding was introduced as a security fix.

      The vulnerability exists if a developer uses `safe` filter or `Meta.safe` incorrectly, especially when rendering user-provided content or data that is not properly sanitized before being set as a component attribute.
  - security test case:
      1. Create a new Django project and install django-unicorn.
      2. Create a Django app named `vuln_test`.
      3. In `vuln_test/components`, create a component named `xss_test.py` with the following content:
```python
from django_unicorn.components import UnicornView

class XssTestView(UnicornView):
    unsafe_content = ""

    def set_unsafe_content(self):
        self.unsafe_content = '<img src=x onerror=alert("XSS")>'
```
      4. In `vuln_test/templates/unicorn`, create a template named `xss-test.html` with the following content:
```html
<div>
    {{ unsafe_content|safe }}
    <button unicorn:click="set_unsafe_content">Trigger XSS</button>
</div>
```
      5. In `vuln_test/views.py`, create a view to render a template that includes the component:
```python
from django.shortcuts import render

def xss_view(request):
    return render(request, 'xss_template.html')
```
      6. In `vuln_test/templates`, create a template named `xss_template.html` with the following content:
```html
{% load unicorn %}
<html>
<head>
    {% unicorn_scripts %}
</head>
<body>
    {% csrf_token %}
    {% unicorn 'xss-test' %}
</body>
</html>
```
      7. In `vuln_test/urls.py`, add the following URL pattern:
```python
from django.urls import path
from .views import xss_view

urlpatterns = [
    path('xss/', xss_view, name='xss_view'),
]
```
      8. Include `vuln_test` in `INSTALLED_APPS` and update project `urls.py` to include `vuln_test.urls`.
      9. Run the Django development server.
      10. Open the `/xss/` URL in a browser.
      11. Click the "Trigger XSS" button.
      12. Observe that an alert box with "XSS" is displayed, confirming the vulnerability.
