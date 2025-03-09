- Vulnerability Name: Cross-Site Scripting (XSS) in Template Rendering

- Description:
  - An attacker can inject malicious JavaScript code into user-controlled input fields within a Django Unicorn component.
  - When the component re-renders and displays this input in the template without proper sanitization, the malicious script executes in the user's browser.
  - Step-by-step trigger:
    1. A user interacts with a Django Unicorn component that includes an input field bound to a component property via `unicorn:model`.
    2. The attacker enters malicious JavaScript code (e.g., `<script>alert("XSS")</script>`) into the input field.
    3. An action is triggered within the component that causes a re-render (e.g., button click, model update).
    4. During re-rendering, the component template displays the attacker's input, including the malicious script, without sanitization if `safe` filter or attribute is used. Otherwise, default behaviour of `BeautifulSoup` escapes HTML entities.
    5. The user's browser executes the injected JavaScript code when rendering the component, leading to XSS if `safe` filter or attribute is used.

- Impact:
  - Successful XSS attacks can have severe consequences, including:
    - **Account Takeover:** Stealing session cookies or credentials to impersonate users.
    - **Data Theft:** Accessing sensitive user data or application data.
    - **Malware Distribution:** Redirecting users to malicious websites or injecting malware.
    - **Defacement:** Modifying the content of the web page seen by the user.
    - **Denial of Service (indirect):**  Causing excessive client-side processing that degrades the user experience or crashes the browser.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - Based on the changelog (`v0.36.0`), HTML encoding was introduced as a security fix to prevent XSS attacks. Responses are HTML encoded by default.
  - Documentation for `views.md` and source code analysis confirms the existence of `safe` Meta attribute and `safe` template filter to explicitly allow HTML content, implying that by default, content is treated as unsafe and encoded.
  - Source code analysis of `django_unicorn/utils.py` reveals a `sanitize_html` function. This function is used to escape HTML characters for JSON output, specifically within the `json_script` context, and is not used for general template rendering for HTML templates.
  - Analysis of `django_unicorn/components/unicorn_template_response.py` in `UnicornTemplateResponse._desoupify()` confirms that `BeautifulSoup` is used to parse and re-serialize the template. The serialization uses `soup.encode(formatter=UnsortedAttributes()).decode("utf-8")`. `BeautifulSoup` by default escapes HTML entities, providing automatic HTML encoding, which is the primary mitigation.
  - Test case `test_process_component_request.py` shows that HTML entities are encoded by default. `test_safe_html_entities_not_encoded` shows that `safe` Meta attribute bypasses encoding.

- Missing Mitigations:
  - While output encoding is likely in place by default due to BeautifulSoup's default behavior, developers can bypass it using `safe` filter or Meta attribute.
    - **Contextual Output Encoding:** While HTML entity encoding is happening by default, it's important to ensure there are no scenarios where contextual encoding is missed, especially if user input is used in JavaScript or URL contexts. Currently, the primary encoding is HTML entity encoding provided by `BeautifulSoup`. Deeper analysis is needed to confirm if other contexts are handled.
    - **Input Sanitization (Defense in Depth):** Although output encoding is the primary defense for XSS, input sanitization could be considered as a defense-in-depth measure. However, output encoding is generally preferred and currently implemented as the primary mitigation.
    - **Content Security Policy (CSP):** Implementing a strong Content Security Policy (CSP) is a valuable missing mitigation to further reduce the impact of XSS vulnerabilities. CSP is not currently implemented.
    - **Auditing use of `safe` filter/Meta attribute:** Developers need to be acutely aware of the security implications of using the `safe` filter or `safe` Meta attribute. There should be prominent documentation warnings and potentially linting rules against using these with unsanitized user input. This is currently missing beyond basic documentation.

- Preconditions:
  - The application must be using Django Unicorn components.
  - A component must render user-controlled input from a `unicorn:model` in its template.
  - The output encoding/sanitization is bypassed by using `safe` filter or Meta attribute. Default encoding should prevent XSS unless bypassed.

- Source Code Analysis:
  - **Template Rendering Process:** (No new findings from reviewed files)
    - `UnicornView.render()` in `django_unicorn/components/unicorn_view.py` calls `render_to_response()`.
    - `render_to_response()` uses `UnicornTemplateResponse` as `response_class`.
    - `UnicornTemplateResponse.render()` in `django_unicorn/components/unicorn_template_response.py` is the core rendering function.
    - It calls `super().render()` to get the initial rendered content from Django templates.
    - It then uses `BeautifulSoup(content, features="html.parser")` to parse the HTML content.
    - Unicorn specific attributes (`unicorn:id`, `unicorn:name`, etc.) are added to the root element of the component within the BeautifulSoup object.
    - `UnicornTemplateResponse._desoupify(soup)` is called to serialize the BeautifulSoup object back to HTML.
    - `_desoupify` uses `soup.encode(formatter=UnsortedAttributes()).decode("utf-8")` to encode the soup. **Crucially, BeautifulSoup's default encoding mechanism during `encode` will escape HTML entities.**
  - **`sanitize_html` function:** (No new findings from reviewed files)
    - Found in `django_unicorn/utils.py`.
    - Used to escape HTML special characters for JSON output using `html.translate(_json_script_escapes)`.
    - **Not used for general template rendering.** Its purpose is specifically for `json_script` context, not for escaping variables rendered in HTML templates directly. Test `test_utils.py` confirms it escapes `<script>` tags.
  - **`safe` filter and Meta attribute:** (No new findings from reviewed files)
    - Documentation mentions `safe` filter and `safe` Meta attribute to allow raw HTML. This mechanism would indeed bypass the default HTML encoding if used improperly with user input. Test `test_process_component_request.py` confirms `safe` attribute bypasses encoding.
  - **`test_is_html_well_formed.py` and `test_unicorn_template_response.py`**: These test files indicate a focus on HTML structure and parsing, further reinforcing the reliance on `BeautifulSoup` for template processing and implicitly for HTML encoding.

- Security Test Case:
  - Step 1: Create a simple Django Unicorn component with an input field bound to a property (e.g., `text`) using `unicorn:model`.
  - Step 2: In the component's template, render the `text` property directly using `{{ text }}`.
  - Step 3: Create a Django view that includes this component in a template and serves it.
  - Step 4: Access the page in a browser.
  - Step 5: In the input field, enter the following XSS payload: `<script>alert("XSS Vulnerability")</script>`.
  - Step 6: Trigger an action in the component that causes a re-render. This could be typing in another input or clicking a button.
  - Step 7: Observe if an alert box with "XSS Vulnerability" appears.
    - If the alert box does not appear and the payload is rendered as plain text (e.g., `&lt;script&gt;alert("XSS Vulnerability")&lt;/script&gt;`), it suggests that HTML encoding is working by default.
    - If the alert box appears, it indicates a potential issue if default encoding is bypassed or not working as expected in some context.
  - Step 8: To test bypassing encoding, modify the template to use the `safe` template filter: `{{ text|safe }}` and repeat steps 5-7. If the alert box appears now, it confirms that using `safe` bypasses encoding and introduces XSS if used with unsanitized user input.
  - Step 9: Further test with different XSS payloads, including event handlers (`<img src=x onerror=alert('XSS')>`), and different contexts (within attributes, URLs) to comprehensively assess XSS protection and the behavior of `safe` filter. Also test using `safe` Meta attribute in the component definition to verify if it has the same bypassing effect as the `safe` template filter.
