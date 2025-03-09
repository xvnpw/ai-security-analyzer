## Vulnerability List for django-unicorn project

### Potential Cross-Site Scripting (XSS) via `safe` meta option

- Description:
    1. A developer creates a Django Unicorn component and defines a `Meta` class within it.
    2. Inside the `Meta` class, the developer specifies a tuple or list named `safe` that includes attribute names of the component.
    3. This `safe` option instructs django-unicorn to bypass HTML entity encoding for the specified attributes when rendering the component's template.
    4. If the developer then renders the attribute in the template using `{{ attribute_name }}` and the attribute's value is derived from unsanitized user input, it becomes possible for an attacker to inject malicious JavaScript code.
    5. When a user views the page, the injected JavaScript code executes in their browser because django-unicorn does not encode HTML entities for the attribute, leading to a Cross-Site Scripting (XSS) vulnerability.

- Impact:
    Successful exploitation of this vulnerability allows an attacker to execute arbitrary JavaScript code in the context of the victim's browser when they view the affected page. This can lead to:
    - Session hijacking: Stealing the user's session cookies, allowing the attacker to impersonate the user.
    - Cookie theft: Accessing sensitive information stored in cookies.
    - Redirection to malicious websites: Redirecting the user to a phishing or malware distribution site.
    - Defacement: Altering the content of the webpage visible to the user.
    - Execution of arbitrary actions on behalf of the user: Performing actions that the user is authorized to do on the application.

- Vulnerability rank: high

- Currently implemented mitigations:
    - By default, django-unicorn automatically encodes HTML entities for all component attributes when rendering templates. This encoding prevents the browser from interpreting HTML tags and JavaScript code within the attribute values, thus mitigating XSS in most cases.
    - The `safe` meta option has to be explicitly defined by the developer for specific attributes, meaning the XSS risk is only present if the developer consciously chooses to disable the default HTML entity encoding.

- Missing mitigations:
    - **Explicit Warning in Documentation and Code:** There's no prominent warning in the code or documentation that clearly highlights the severe security risks associated with using the `safe` meta option. A security-focused warning in the documentation, along with a code-level comment or even a linting check, could alert developers to the potential XSS vulnerabilities if `safe` is misused.
    - **Sanitization Guidance and Tools:** Django Unicorn could provide or link to best practices and tools for sanitizing user inputs, especially when developers intend to use the `safe` option. This could include recommendations for using Django's built-in HTML sanitization tools or other established libraries.
    - **Template Rendering Security Review:**  A more in-depth review of the template rendering process could identify opportunities to enforce safer defaults or provide more granular control over HTML escaping, reducing the risk of developers inadvertently introducing XSS vulnerabilities.

- Preconditions:
    1. A Django Unicorn component must be implemented with a `Meta` class that includes the `safe` option, listing one or more attributes.
    2. One of the attributes listed in `safe` (`unsafe_content` in the example below) must be rendered in the component's template without any further HTML sanitization (e.g., using `{{ unsafe_content }}`).
    3. The value of this `safe` attribute must be directly or indirectly controllable by user input and must not be properly sanitized before being set as the component's attribute value.

- Source code analysis:
    1. Examine `django_unicorn\components\unicorn_template_response.py`: This file handles the rendering of Unicorn components. Look for how component attributes are processed and how the `safe` meta option is handled during rendering.
    2. Check `django_unicorn\components\unicorn_view.py`:  Inspect the `UnicornView` class and its `get_frontend_context_variables` method. This method is responsible for preparing the data that is passed to the frontend, and it's where the `safe` meta option is likely processed.
    3. Review `tests\views\test_process_component_request.py`: The tests `test_html_entities_encoded` and `test_safe_html_entities_not_encoded` demonstrate the behavior of the `safe` meta option. `FakeComponentSafe` has `safe = ("hello",)` in its Meta class.
    ```python
    # tests\views\test_process_component_request.py

    class FakeComponentSafe(UnicornView):
        template_name = "templates/test_component_variable.html"
        hello = ""
        class Meta:
            safe = ("hello",)
    ```
    4. In `test_safe_html_entities_not_encoded`, the assertion `assert "<b>test1</b>" in response["dom"]` confirms that when `safe` is used, HTML tags are rendered as HTML, not encoded as entities.
    ```python
    # tests\views\test_process_component_request.py

    def test_safe_html_entities_not_encoded(client):
        data = {"hello": "test"}
        action_queue = [ ... ]
        response = post_and_get_response( ..., component_name="FakeComponentSafe", ...)
        assert "<b>test1</b>" in response["dom"]
    ```
    5. This mechanism, while providing flexibility, bypasses default XSS protection if developers are not careful about sanitizing data when using `safe`.

- Security test case:
    1. Create a new test component named `XssVulnerableComponent` in `tests\views\fake_components.py`:
        ```python
        # tests\views\fake_components.py
        class XssVulnerableComponent(UnicornView):
            template_name = "templates/test_component_xss.html"
            unsafe_content = ""

            class Meta:
                safe = ("unsafe_content",)
        ```
    2. Create a template `templates/test_component_xss.html`:
        ```html
        {# templates/test_component_xss.html #}
        <div id="xss-test">
            {{ unsafe_content }}
        </div>
        ```
    3. Create a test function in `tests\views\message\test_xss.py`:
        ```python
        # tests\views\message\test_xss.py
        from tests.views.message.utils import post_and_get_response

        def test_xss_safe_option(client):
            xss_payload = "<script>alert('XSS Vulnerability')</script>"
            data = {"unsafe_content": ""}
            action_queue = [
                {
                    "payload": {"name": "unsafe_content", "value": xss_payload},
                    "type": "syncInput",
                }
            ]
            response = post_and_get_response(
                client,
                url="/message/tests.views.fake_components.XssVulnerableComponent",
                data=data,
                action_queue=action_queue,
            )

            assert not response["errors"]
            assert response["data"].get("unsafe_content") == xss_payload
            assert xss_payload in response["dom"]
            assert "<div id=\"xss-test\"> <script>alert('XSS Vulnerability')</script> </div>" == response["dom"].strip()
            # Further manual verification is needed to confirm that the alert is actually triggered in a browser when rendering this dom.
        ```
    4. Run the test. The assertion `assert xss_payload in response["dom"]` confirms that the payload is rendered as raw HTML in the DOM, indicating a potential XSS vulnerability. To fully verify, you would need to manually render the `response["dom"]` in a browser and confirm that the JavaScript `alert('XSS Vulnerability')` is executed.
