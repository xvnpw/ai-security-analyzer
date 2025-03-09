* Vulnerability Name: Cross-Site Scripting (XSS) through `safe` filter misuse

* Description:
    1. A developer uses the `safe` filter in a Django Unicorn component template to render user-provided data without proper sanitization.
    2. An attacker crafts malicious input containing JavaScript code.
    3. The attacker submits this malicious input, which is processed by the Django Unicorn component and rendered in the template using the `safe` filter.
    4. Because the `safe` filter bypasses the default HTML encoding, the malicious JavaScript code is executed in the victim's browser.

* Impact:
    - Execution of malicious JavaScript code in the victim's browser.
    - Potential for session hijacking, cookie theft, account takeover, defacement, or redirection to malicious sites.
    - Full compromise of the user's interaction with the application.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - By default, Django Unicorn automatically HTML encodes all dynamic content rendered in templates to prevent XSS.
    - Introduced in version v0.36.0 as a security fix for CVE-2021-42053.
    - Mitigation is described in `changelog.md`: "responses will be HTML encoded going forward".
    - Mitigation is configurable via `safe` attribute in `Meta` class or `safe` template filter as described in `docs/source/views.md` and `docs/source/templates.md`.
    - The `django_unicorn.utils.sanitize_html` function is used by default to escape HTML characters, as seen in `django_unicorn/utils.py` and tested in `tests/test_utils.py`.
    - Tests in `tests/views/test_process_component_request.py` like `test_html_entities_encoded` confirm that HTML entities are encoded by default, and `test_safe_html_entities_not_encoded` verifies the `safe` attribute behavior.

* Missing Mitigations:
    - Explicit warning in the documentation about the risks of using the `safe` filter with user-provided data. This warning should be prominently placed in the documentation sections about templates and data binding.
    - Best practice guidelines on when and how to use the `safe` filter securely, emphasizing the need for sanitization of user-provided content before rendering it with `safe`. Suggest using Django's `escape` filter or a dedicated sanitization library like Bleach for user inputs before applying `safe`.
    - Security linting or static analysis tools to detect potentially unsafe usage of the `safe` filter in Django Unicorn templates. This could include custom checks in template linters or IDE plugins that warn developers when `safe` is used on variables that might originate from user input.
    - Security test cases specifically demonstrating the XSS vulnerability when `safe` is misused and confirming that default behavior is safe. These tests should be part of the project's test suite to prevent regressions and clearly illustrate the risk to developers.  The provided test case in the current vulnerability description should be added to the test suite.

* Preconditions:
    - A Django Unicorn component template must render user-provided data.
    - The developer must intentionally use the `safe` filter on the user-provided data, bypassing the default HTML encoding.
    - An attacker must be able to influence the user-provided data that is rendered.

* Source Code Analysis:
    - The file `django_unicorn/components/unicorn_template_response.py` handles template rendering and, by default, utilizes `django_unicorn.utils.sanitize_html` to ensure HTML encoding.
    - The `sanitize_html` function in `django_unicorn/utils.py` uses `html.translate(_json_script_escapes)` effectively escaping HTML special characters to prevent basic XSS.
    - Files like `tests/views/test_process_component_request.py` contain tests (`test_html_entities_encoded`) that explicitly verify the default HTML encoding behavior.
    - The documentation files (`docs/source/views.md`, `docs/source/templates.md`) clearly explain the `safe` attribute and filter as opt-in mechanisms to disable default sanitization, implicitly placing the responsibility of safe usage on the developer.
    - No new code in the analyzed files introduces XSS vulnerabilities. The risk remains in the potential misuse of the `safe` functionality by developers, which is already documented.

* Security Test Case:
    1. Create a Django Unicorn component that renders user-provided input using the `safe` filter.
        ```python
        # unsafe_component.py
        from django_unicorn.components import UnicornView

        class UnsafeView(UnicornView):
            user_input = ""

            class Meta:
                safe = ("user_input",) # or use |safe filter in template

            def set_input(self, input_value):
                self.user_input = input_value
        ```
        ```html
        <!-- unsafe_component.html -->
        <div>
            <input type="text" unicorn:model.defer="user_input" id="user_input">
            <button unicorn:click="set_input(user_input)">Set Input</button>
            <div id="output">
                {{ unicorn.user_input }} {# Vulnerable because Meta safe attribute is set in component #}
            </div>
        </div>
        ```
    2. Deploy the Django application with this component to a publicly accessible instance.
    3. As an attacker, access the page containing the `unsafe_component`.
    4. In the input field, enter a malicious JavaScript payload, for example: `<img src='x' onerror='alert(\"XSS Vulnerability\")'>`.
    5. Click the "Set Input" button.
    6. Observe that an alert box with "XSS Vulnerability" is displayed in the browser. This demonstrates that the JavaScript code from the input was executed, confirming the XSS vulnerability.
    7. To test with `safe` filter in template instead of `Meta` attribute, modify the template like this and repeat steps 4-6:
        ```html
        <!-- unsafe_component.html -->
        <div>
            <input type="text" unicorn:model.defer="user_input" id="user_input">
            <button unicorn:click="set_input(user_input)">Set Input</button>
            <div id="output">
                {{ unicorn.user_input|safe }} {# Vulnerable because of |safe filter #}
            </div>
        </div>
