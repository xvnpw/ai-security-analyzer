- Vulnerability Name: Reflected Cross-Site Scripting (XSS) in Component Rendering

- Description:
    1. An attacker crafts a malicious URL or input that, when processed by a Django Unicorn component, includes unsanitized JavaScript code.
    2. A user, typically a website visitor, interacts with the application in a way that triggers the rendering of the vulnerable component with the attacker's malicious input. This could be through form submission, URL parameters, or other input mechanisms that django-unicorn handles and re-renders.
    3. Django Unicorn's component rendering process fails to properly sanitize the attacker-controlled input if `Meta.safe` is used. By default, HTML encoding is applied.
    4. If `Meta.safe` is enabled for a field rendering user input, the malicious JavaScript is injected into the HTML content that is dynamically updated by Django Unicorn and sent to the user's browser.
    5. The user's browser executes the injected JavaScript code, which can perform actions such as stealing cookies, redirecting the user to a malicious website, or defacing the web page.

- Impact:
    - Account Takeover: Attackers can potentially steal session cookies, leading to account hijacking.
    - Data Theft: Sensitive information displayed on the page could be exfiltrated.
    - Website Defacement: The attacker can modify the content of the web page seen by the user.
    - Redirection to Malicious Sites: Users can be redirected to phishing websites or sites hosting malware.
    - Execution of Arbitrary JavaScript: Full control over the user's browser within the context of the vulnerable web page.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - Based on changelog v0.36.0, "Security fix: for CVE-2021-42053 to prevent XSS attacks ... responses will be HTML encoded going forward". This suggests there was a vulnerability and mitigation was implemented. Changelog v0.36.1 also mentions "More complete handling to prevent XSS attacks." and "More verbose error messages when components can't be loaded". Changelog v0.29.0 mentions "Sanitize initial JSON to prevent XSS". Changelog v0.36.0 indicates "Breaking changes - responses will be HTML encoded going forward".
    - `views.md` documentation mentions `Meta.safe` option: "By default, unicorn HTML encodes updated field values to prevent XSS attacks. You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple." This implies that encoding is enabled by default and developers need to explicitly disable it, which is a good security practice.
    - `utils.py` file includes `sanitize_html` function, indicating awareness of sanitization needs.
    - In `components\unicorn_template_response.py`, `UnicornTemplateResponse` renders components and uses `BeautifulSoup` to manipulate HTML and `_desoupify` function which encodes HTML using `soup.encode(formatter=UnsortedAttributes()).decode("utf-8")`. This encoding is part of the default mitigation. The `test_desoupify` test in `test_unicorn_template_response.py` confirms the HTML encoding.
    - In `views\__init__.py`, before rendering components, attributes listed in `Meta.safe` are marked as safe using `mark_safe`. This is intended for cases where developers intentionally want to render unescaped HTML, but it requires careful handling and input validation.
    - Tests in `test_process_component_request.py`, specifically `test_html_entities_encoded`, demonstrate that by default, HTML entities are encoded, confirming the default mitigation.

- Missing Mitigations:
    - While HTML encoding is the default behavior, the `Meta.safe` option allows developers to bypass this protection. If `safe` is used without rigorous sanitization or validation of user-provided data, it directly re-introduces XSS vulnerabilities.
    - The documentation highlights the `safe` option, but it needs to strongly emphasize the security implications and best practices for its use. Developers might misunderstand the risk and use `safe` incorrectly.
    - It is not clear from the provided files the exact implementation of HTML encoding and which encoding function is used by default, and whether it covers all potential XSS attack vectors. The `_desoupify` function in `UnicornTemplateResponse` performs encoding, but the specifics and robustness need further investigation.
    - There is a risk that developers might use `mark_safe` incorrectly in other parts of the component or related code, bypassing intended sanitization.

- Preconditions:
    - A Django Unicorn component must be rendering user-controlled data dynamically into the HTML template.
    - A developer must have explicitly used the `safe` meta option in the component's `Meta` class for a field that renders unsanitized user input.

- Source Code Analysis:
    - `changelog.md`: Versions 0.29.0, 0.36.0, and 0.36.1 explicitly mention security fixes related to XSS, indicating that XSS vulnerabilities were a concern and addressed in the past. Version 0.36.0 implemented default HTML encoding as a mitigation strategy: "responses will be HTML encoded going forward".
    - `docs\source\views.md`: The documentation for `Meta.safe` explains the default HTML encoding and the opt-out mechanism using `safe`. It implicitly warns about the risks, but could be more explicit and provide security best practices.
    - `django_unicorn\utils.py`: Contains `sanitize_html` function, which escapes HTML/XML special characters. This function is available for sanitization purposes but its default usage is not explicitly shown in these files.
    - `django_unicorn\components\unicorn_template_response.py`: The `UnicornTemplateResponse` class is responsible for rendering the component. The `render` method uses `BeautifulSoup` to parse and manipulate the template content. The `_desoupify` method performs HTML encoding using `soup.encode(formatter=UnsortedAttributes()).decode("utf-8")`. This function seems to be the primary mechanism for HTML encoding. The test `test_desoupify` in `test_unicorn_template_response.py` confirms this encoding process.
    - `django_unicorn\views\__init__.py`: In the `_process_component_request` function, attributes listed in `Meta.safe` are marked as safe using `mark_safe` *before* rendering. This means that for fields marked as `safe`, the default HTML encoding performed by `_desoupify` will be bypassed, and the content will be rendered as is, potentially leading to XSS if user input is rendered without further sanitization in the template.
    - `django_unicorn\tests\views\test_process_component_request.py`: The tests `test_html_entities_encoded` and `test_safe_html_entities_not_encoded` directly demonstrate the behavior of HTML encoding and the `safe` meta option. `test_html_entities_encoded` shows that without `Meta.safe`, HTML is encoded. `test_safe_html_entities_not_encoded` shows that with `Meta.safe`, HTML is not encoded, confirming the bypass of default mitigation.

- Security Test Case:
    1. Create a Django project with Django Unicorn installed.
    2. Define a Django Unicorn component that takes user input and renders it unsafely using the `safe` meta option.
        ```python
        # components/xss_component.py
        from django_unicorn.components import UnicornView

        class XSSView(UnicornView):
            unsafe_data = ""

            class Meta:
                safe = ("unsafe_data",) # Explicitly marking as safe to demonstrate vulnerability

            def mount(self):
                self.unsafe_data = self.component_kwargs.get("user_input", "")

        ```
        ```html
        {# templates/unicorn/xss_component.html #}
        <div>
            <p>Unsafe Input: {{ unsafe_data }}</p>
        </div>
        ```
    3. Create a Django view and template to include the vulnerable component, passing user-controlled input as a component kwarg.
        ```python
        # views.py
        from django.shortcuts import render
        from .components.xss_component import XSSView

        def xss_test_view(request):
            user_input = request.GET.get('input', '')
            return render(request, 'xss_test.html', {'user_input': user_input})
        ```
        ```html
        {# templates/xss_test.html #}
        {% load unicorn %}
        <html>
        <head>
            {% unicorn_scripts %}
            <title>XSS Test</title>
        </head>
        <body>
            {% csrf_token %}
            {% unicorn 'xss-view' user_input=user_input %}
        </body>
        </html>
        ```
    4. Configure `urls.py` to route to the test view.
        ```python
        # urls.py
        from django.urls import path
        from . import views
        from django.conf.urls import include


        urlpatterns = [
            path('xss_test/', views.xss_test_view, name='xss_test'),
            path("unicorn/", include("django_unicorn.urls")),
        ]
        ```
    5. Run the Django development server.
    6. Craft a malicious URL to test for XSS. For example: `http://127.0.0.1:8000/xss_test/?input=<script>alert("XSS Vulnerability");</script>`
    7. Access the malicious URL in a web browser.
    8. Observe if the JavaScript `alert("XSS Vulnerability");` is executed. If an alert box appears, the XSS vulnerability is confirmed.
    9. **Expected Result:** An alert box should appear, demonstrating that the JavaScript code was executed, confirming the XSS vulnerability when `safe` is used improperly.
    10. **Reference to existing tests:** The tests `test_safe_html_entities_not_encoded` in `django_unicorn\tests\views\test_process_component_request.py` effectively serve as an automated security test case, confirming the vulnerability when `Meta.safe` is enabled and user input is not sanitized. Running this test, after adjusting the component to render the `hello` attribute directly in the template when `Meta.safe` is used, would demonstrate the XSS vulnerability.
