- Vulnerability Name: Cross-Site Scripting (XSS) through `Meta.safe` or `safe` template filter

- Description:
  - Step 1: An attacker injects malicious JavaScript code as user-provided data (e.g., through a form field or URL parameter).
  - Step 2: A Django Unicorn component is designed to render a template that includes this user-provided data.
  - Step 3: The developer, intending to render HTML or believing the data to be safe, uses `Meta.safe` in the component's `Meta` class or the `safe` template filter in the template when displaying this user-provided data.
  - Step 4: Django Unicorn, following the developer's instruction, bypasses the default HTML encoding for this specific data, allowing it to be rendered as raw HTML.
  - Step 5: The server-rendered HTML, now containing the attacker's malicious JavaScript code, is sent to the client-side and injected into the DOM.
  - Step 6: When the client-side JavaScript executes, the malicious code provided by the attacker is executed within the user's browser. This can lead to various attacks, including stealing sensitive information like cookies or session tokens, performing actions on behalf of the user, or redirecting the user to malicious websites.

- Impact:
  - Successful exploitation of this vulnerability can lead to Cross-Site Scripting (XSS).
  - An attacker could potentially perform actions such as:
    - Account takeover by stealing session cookies.
    - Defacement of the web page.
    - Redirection of users to malicious sites.
    - Theft of sensitive user data.
    - Execution of arbitrary JavaScript code in the victim's browser.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - By default, Django Unicorn automatically HTML-encodes all component data rendered in templates to prevent XSS. This is a global mitigation applied to all data unless explicitly bypassed.
  - This default encoding is mentioned in `docs\source\views.md` under "Meta" -> "safe" and in `docs\source\changelog.md` for version 0.36.0 as a security fix for CVE-2021-42053.

- Missing Mitigations:
  - There are no explicit runtime or compile-time checks to warn developers against the potential risks of using `Meta.safe` or the `safe` template filter.
  - The documentation, while mentioning `Meta.safe`, could be improved to prominently feature a security warning against its misuse and clearly explain the XSS risks involved when bypassing HTML encoding.

- Preconditions:
  - Precondition 1: The Django Unicorn application must render user-provided data within a component template.
  - Precondition 2: A developer must explicitly bypass Django Unicorn's default HTML encoding for this user-provided data by either:
    - Adding the field name to the `safe` tuple within the `Meta` class of the component view (e.g., `class Meta: safe = ("user_input", )`).
    - Using the `safe` template filter when rendering the data in the template (e.g., `{{ user_input|safe }}`).
  - Precondition 3: An attacker must be able to control the user-provided data that is being rendered (e.g., through input fields, URL parameters, or other means of data injection).

- Source Code Analysis:
  - Step 1: Review `docs\source\views.md` and `docs\source\templates.md` which document the `safe` attribute in the `Meta` class and the `safe` template filter. These sections explain how to bypass the default HTML encoding.
  - Step 2: Analyze `docs\source\changelog.md` for version 0.36.0. This changelog entry highlights the introduction of default HTML encoding as a security fix for CVE-2021-42053 and explicitly mentions using `safe` to opt-in to the previous behavior (no encoding).
  - Step 3: The code examples in `docs\source\views.md` and `docs\source\templates.md` for `Meta.safe` and `safe` template filter, while demonstrating the functionality, do not include prominent security warnings about the risks of XSS if misused.
  - Step 4: There is no code in the provided files that automatically prevents or warns against the insecure use of `Meta.safe` or `safe` template filter. The library relies on the developer to use these features responsibly.

- Security Test Case:
  - Step 1: Create a new Django Unicorn component named `xss_safe_component`.
  - Step 2: In `xss_safe_component.py`, define a component view `XssSafeView` with a public property `user_input` and include a `Meta` class with `safe = ("user_input", )`:
    ```python
    # xss_safe_component.py
    from django_unicorn.components import UnicornView

    class XssSafeView(UnicornView):
        user_input = ""

        class Meta:
            safe = ("user_input", )
    ```
  - Step 3: Create a template `xss_safe_component.html` that renders the `user_input` property:
    ```html
    {# xss_safe_component.html #}
    <div>
      <p>User Input: {{ user_input }}</p>
    </div>
    ```
  - Step 4: Create a Django view to render the `XssSafeView` component and pass user-controlled input as context:
    ```python
    # views.py
    from django.shortcuts import render
    from .unicorn.components.xss_safe_component import XssSafeView

    def xss_test_view(request):
        user_input = request.GET.get('input', '')
        return render(request, 'xss_test.html', {'user_input': user_input})
    ```
  - Step 5: Create a template `xss_test.html` to include the `xss_safe_component` and pass the `user_input` context variable to the component:
    ```html
    {# xss_test.html #}
    {% load unicorn %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        {% unicorn 'xss-safe-component' user_input=user_input %}
    </body>
    </html>
    ```
  - Step 6: Run the Django development server.
  - Step 7: As an attacker, craft a URL to the `xss_test_view` with malicious JavaScript in the `input` parameter, for example: `http://127.0.0.1:8000/xss_test/?input=<img src=x onerror=alert('XSS_Vulnerability')>`.
  - Step 8: Open the crafted URL in a web browser.
  - Step 9: Observe that an alert box with the message 'XSS_Vulnerability' appears. This confirms that the JavaScript code injected through the `input` parameter was executed because `Meta.safe` prevented HTML encoding, thus demonstrating a Cross-Site Scripting vulnerability.
