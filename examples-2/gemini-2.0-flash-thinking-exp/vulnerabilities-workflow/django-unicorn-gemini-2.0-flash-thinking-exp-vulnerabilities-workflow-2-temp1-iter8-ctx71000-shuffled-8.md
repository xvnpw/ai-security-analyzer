### Vulnerability List for Django Unicorn Project

* Vulnerability Name: Improperly used `safe` Meta option leading to XSS
* Description:
    * Step 1: A developer creates a Django Unicorn component and, intending to render user-provided content without HTML escaping, incorrectly adds a property to the `safe` list within the `Meta` class.
    * Step 2: The component's template directly renders this property, which is bound to user input through `unicorn:model`, without any additional sanitization.
    * Step 3: An attacker inputs malicious JavaScript code (e.g., `<img src=x onerror=alert('XSS')>`) into the input field associated with the vulnerable property.
    * Step 4: When the component updates due to user interaction or an action, the server-side component re-renders, and the unsanitized, malicious input is sent back to the client.
    * Step 5: The client-side JavaScript merges the updated HTML, including the malicious script, into the DOM.
    * Step 6: The injected JavaScript executes in the user's browser, leading to Cross-Site Scripting (XSS).
* Impact:
    * Successful exploitation allows an attacker to execute arbitrary JavaScript code in a victim's browser.
    * This can lead to serious security breaches, including:
        * Account takeover: Stealing session cookies or credentials to impersonate the user.
        * Data theft: Accessing sensitive information visible to the user.
        * Defacement: Modifying the content of the web page seen by the user.
        * Redirection to malicious sites: Redirecting the user to phishing websites or malware distribution points.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    * Default HTML Encoding: Django Unicorn, by default, encodes all component properties when rendering HTML to prevent XSS. This is the primary, built-in mitigation.
    * Documentation: The documentation explicitly warns against putting sensitive data into public properties and explains the purpose and usage of the `safe` and `javascript_exclude` Meta options, emphasizing the security implications of bypassing HTML encoding.
* Missing Mitigations:
    * Template Linting/Static Analysis: A template linting tool or static analysis could detect and warn developers about the potential misuse of the `safe` Meta option, especially when used with user-controlled input rendered without sanitization in the template.
    * Runtime Warnings: In development mode, Django Unicorn could potentially issue a warning if it detects a component using the `safe` Meta option on a property that appears to be directly bound to user input without explicit sanitization in the template.
    * Scoped Sanitization Directives: Instead of a blanket `safe` option for an entire property, consider more granular control, such as template directives that allow developers to selectively mark specific outputs as safe after explicit sanitization, rather than disabling encoding by default for the whole property.
* Preconditions:
    * Developer must explicitly add a property to the `safe` list in the component's `Meta` class.
    * The property marked as `safe` must be directly rendered in the template without any further HTML sanitization.
    * The property must be bound to user-controlled input, typically through `unicorn:model`.
* Source Code Analysis:
    * File: `..\django-unicorn\docs\source\views.md`
        * The documentation for the `safe` Meta option clearly states its purpose: "By default, `unicorn` HTML encodes updated field values to prevent XSS attacks. You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple."
        * The documentation provides an example (`safe-example.py` and `safe-example.html`) demonstrating the usage of the `safe` option, highlighting that it bypasses the default HTML encoding.
        * There are no code-level mitigations within Django Unicorn to prevent the misuse of the `safe` option beyond the default encoding and the documentation itself. The framework relies on the developer's responsible use of this feature.
    * File: `..\django-unicorn\tests\views\test_process_component_request.py`
        * This file contains tests that explicitly demonstrate the behavior of HTML encoding and the `safe` Meta option.
        * `test_html_entities_encoded`: This test uses `FakeComponent` which does *not* have the `safe` Meta option. It verifies that when user input `<b>test1</b>` is synced to the `hello` property and rendered in the template, it is HTML-encoded to `&lt;b&gt;test1&lt;/b&gt;`. This confirms the default HTML encoding mitigation is working.
        * `test_safe_html_entities_not_encoded`: This test uses `FakeComponentSafe` which *does* have `safe = ("hello",)` in its `Meta` class. It verifies that when the same user input `<b>test1</b>` is synced and rendered, it is *not* HTML-encoded and is rendered as `<b>test1</b>`. This confirms that the `safe` option bypasses HTML encoding, and if misused with user input, it can lead to XSS.
        * These tests highlight that Django Unicorn's default behavior is to encode HTML, which is a security mitigation. However, the `safe` Meta option provides a way to disable this encoding, which, if used improperly, creates a vulnerability.

* Security Test Case:
    * Step 1: Create a new Django app named `xss_test` in the `example` project.
    * Step 2: Create a Django Unicorn component named `UnsafeComponent` in `xss_test/unicorn/components/unsafe.py` with the following code:
    ```python
    from django_unicorn.components import UnicornView

    class UnsafeView(UnicornView):
        unsafe_data = ""

        class Meta:
            safe = ("unsafe_data", )
    ```
    * Step 3: Create a Django template for the component at `xss_test/templates/unicorn/unsafe.html` with the following code:
    ```html
    <div>
      <input unicorn:model="unsafe_data" type="text" id="unsafe_input" />
      <div id="output">{{ unsafe_data }}</div>
    </div>
    ```
    * Step 4: Create a Django template to include the component at `xss_test/templates/index.html`:
    ```html
    {% load unicorn %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        {% unicorn 'unsafe' %}
    </body>
    </html>
    ```
    * Step 5: Create a Django view in `xss_test/views.py`:
    ```python
    from django.shortcuts import render

    def index(request):
        return render(request, 'index.html')
    ```
    * Step 6: Configure URLs in `xss_test/urls.py`:
    ```python
    from django.urls import path
    from .views import index

    urlpatterns = [
        path('', index, name='index'),
    ]
    ```
    * Step 7: Include `xss_test` urls and `django_unicorn` in project's `urls.py`:
    ```python
    from django.contrib import admin
    from django.urls import path, include

    urlpatterns = [
        path('admin/', admin.site.urls),
        path('unicorn/', include('django_unicorn.urls')),
        path('', include('xss_test.urls')), # Include xss_test app urls
    ]
    ```
    * Step 8: Add `xss_test` to `INSTALLED_APPS` in `project/settings.py`.
    * Step 9: Run the Django development server: `python example/manage.py runserver`.
    * Step 10: Access `http://127.0.0.1:8000/` in a browser.
    * Step 11: In the input field, enter the following XSS payload: `<img src=x onerror=alert('XSS')>`.
    * Step 12: Click outside the input field or trigger any Unicorn action to cause a component update.
    * Step 13: Observe that an alert box with "XSS" appears in the browser, confirming successful XSS vulnerability.
    * File: `..\django-unicorn\tests\views\test_process_component_request.py` provides an implicit test case.
        * The tests `test_html_entities_encoded` and `test_safe_html_entities_not_encoded` in this file serve as code-level tests demonstrating the vulnerability and the intended behavior of the `safe` option. Running these tests (using `pytest tests/views/test_process_component_request.py`) and inspecting the rendered output in the test assertions will also confirm the vulnerability. Specifically, observing that `test_safe_html_entities_not_encoded` renders raw HTML in the `dom` output confirms the bypass of HTML encoding and the potential for XSS when `safe` is misused.
