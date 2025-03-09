- vulnerability name: Potential Cross-Site Scripting (XSS) through misuse of "safe" template filter and Meta option

- description: Django-unicorn components are rendered using Django templates, which by default automatically escape HTML to prevent XSS. However, django-unicorn provides developers with the ability to bypass this auto-escaping through Django's "safe" template filter and a `safe` Meta option in components. If a developer uses these features to render untrusted user-provided data without proper sanitization, it can lead to a Cross-Site Scripting (XSS) vulnerability. An attacker can inject malicious JavaScript code as user input. If this input is then rendered in a django-unicorn component's template using the `safe` filter or `safe` Meta option, the injected script will execute in the victim's browser.

- impact: A successful XSS attack allows an attacker to execute arbitrary JavaScript code within a victim's browser session. This can result in serious security breaches, including:
    - **Session Hijacking:** Stealing session cookies to impersonate the user and gain unauthorized access to their account.
    - **Cookie Theft:** Accessing sensitive information stored in cookies.
    - **Redirection to Malicious Websites:** Redirecting users to phishing sites or websites hosting malware.
    - **Website Defacement:** Altering the content of the web page to mislead or harm users.
    - **Data Theft:** Potentially accessing sensitive data displayed on the page or transmitted by the user.
Due to the severity of these potential impacts, the vulnerability is ranked as high.

- vulnerability rank: high

- currently implemented mitigations:
    - **Django's Default HTML Escaping:** Django's template engine automatically escapes HTML content by default. This provides a fundamental layer of protection against XSS when developers use standard template variables without explicitly using `safe`.
    - **Documentation of `safe` Feature:** Django-unicorn documentation mentions the `safe` Meta option and the `safe` template filter, implicitly suggesting they are intended for trusted content, indicating an awareness of the associated XSS risks when bypassing auto-escaping.
    - **Security Fix for CVE-2021-42053:** The changelog for version 0.36.0 mentions a security fix (CVE-2021-42053) aimed at preventing XSS attacks, confirming the project's proactive approach to XSS prevention and ensuring HTML encoding in responses.

- missing mitigations:
    - **Stronger Warnings in Documentation:** While `safe` is documented, the documentation needs to prominently and explicitly warn against using `safe` with untrusted user input. It should provide clear, actionable guidelines on when and how to use `safe` securely, emphasizing the risks of misuse.
    - **Best Practices for Sanitization:** The documentation should include comprehensive best practices for sanitizing user input when developers need to render HTML content. It should strongly recommend using Django's built-in `escape` filter or established sanitization libraries for user-provided HTML, instead of completely bypassing escaping with `safe`.
    - **Security Test Cases for `safe` Misuse:**  The project should include dedicated security test cases that specifically target scenarios where developers might incorrectly use `safe`. These tests should demonstrate the XSS vulnerability that arises from such misuse, serving as negative examples to avoid and showcasing secure alternatives. These test cases should be part of the automated test suite to prevent regressions.

- preconditions:
    - **Usage of django-unicorn Components:** The application must be built using django-unicorn components.
    - **Rendering User-Provided Data:** User-provided or user-influenced data must be displayed within these components' templates.
    - **Misuse of `safe` Mechanism:** A developer must have either intentionally or unintentionally used the `safe` template filter (e.g., `{{ variable|safe }}`) or enabled the `safe` Meta option within a component, specifically for rendering user-provided data without adequate sanitization.
    - **Attacker Data Injection:** An attacker needs to identify an entry point to inject malicious data that will be rendered by a django-unicorn component utilizing the `safe` mechanism. This could be through various input vectors such as form fields, URL parameters, or other data sources that are reflected in the component's state and subsequently rendered in the template using `safe`.

- source code analysis:
    - Django-unicorn itself does not introduce XSS vulnerabilities directly. It leverages Django's template rendering engine, which inherently includes auto-escaping.
    - The vulnerability stems from the *intended* use of Django's `safe` features within django-unicorn templates, which are designed to bypass this default escaping.
    - Examining `django_unicorn/utils.py`, the `sanitize_html` function is present but is used for escaping HTML for JSON serialization (e.g., for initial component data in the JavaScript), not for sanitizing template rendering context against XSS.
    - Review of `django_unicorn/components/unicorn_template_response.py` confirms that template rendering is handled using standard Django template mechanisms. No additional, explicit sanitization beyond Django's default auto-escaping is performed by django-unicorn itself during the rendering process.
    - Files like `test_process_component_request.py` in `django-unicorn/tests/views/` contain test cases that *demonstrate* the non-encoding behavior of the `safe` Meta option. These tests confirm that when `safe` is enabled for a component property, HTML content provided as input to that property is rendered *verbatim* in the template, without HTML entity encoding. This directly illustrates the XSS risk if `safe` is used to render untrusted input.
    - The core vulnerability point is not a code defect in django-unicorn, but rather a potential misconfiguration or insecure coding practice by developers who might use the provided `safe` features without fully understanding the security implications when dealing with user-provided data.

- security test case:
    1. **Create a vulnerable django-unicorn component:** Define a component (e.g., `XssComponent`) with a property designed to hold a message, for instance, `user_message`. Configure this component to use the `safe` Meta option for the `user_message` property by adding `safe = ("user_message",)` within the `Meta` class of the component.
    2. **Create a template for the component:** In the component's template, render the `user_message` property: `{{ user_message }}`. Because of the `safe` Meta option, the content of `user_message` will be rendered without HTML escaping.
    3. **Define a view to render the component:** Create a Django view that renders an instance of the `XssComponent`. Map a URL to this view.
    4. **Craft a malicious URL:** As an attacker, construct a URL that, when accessed, will pass a malicious XSS payload as part of the component's data. For example, you might manipulate a query parameter or form input that gets bound to the `user_message` property. A sample payload could be: `<script>alert("XSS Vulnerability");</script>`.
    5. **Access the vulnerable URL:** Open a web browser and navigate to the crafted URL.
    6. **Verify XSS execution:** Observe if the JavaScript code from your payload executes in the browser. If an alert box appears displaying "XSS Vulnerability", it confirms that the XSS vulnerability is present due to the unsafe use of the `safe` Meta option.
    7. **Mitigate the vulnerability in the component:** Modify the `XssComponent` to remove the `safe = ("user_message",)` line from its `Meta` class. This will re-enable Django's default HTML auto-escaping for the `user_message` property.
    8. **Re-test with the malicious URL:** Repeat steps 4-6 using the same malicious URL and payload.
    9. **Verify XSS is mitigated:** Observe that this time, the JavaScript code is *not* executed. Instead, the XSS payload is rendered as plain text (e.g., `&lt;script&gt;alert("XSS Vulnerability");&lt;/script&gt;`), demonstrating that the default auto-escaping now effectively prevents the XSS attack.
    10. **Document test results:** Document the behavior observed in both scenarios (with and without `safe`). Create automated tests that verify the presence of XSS when `safe` is misused and the absence of XSS when default escaping is active, to serve as ongoing regression tests and clear examples of secure and insecure usage patterns for developers.
