- Vulnerability name: Cross-Site Scripting (XSS) vulnerability due to unsafe HTML attribute injection

- Description:
    1. An attacker can inject malicious HTML attributes into DOM elements through user-controlled input fields by manipulating the data sent to the server during component updates.
    2. When a component updates, the server-side rendered HTML, which includes the injected attributes, is sent back to the client.
    3. The client-side JavaScript merges this HTML into the existing DOM using morphdom, effectively injecting the malicious attributes into the DOM elements.
    4. If these injected attributes are event handlers (e.g., `onload`, `onerror`, `onmouseover`), they can execute arbitrary JavaScript code when the element is processed by the browser.
    5. This vulnerability can be triggered through any input field that uses `unicorn:model` and whose value is reflected back into the HTML attributes of the component.

- Impact:
    - An attacker can execute arbitrary JavaScript code in the victim's browser.
    - This can lead to session hijacking, cookie theft, defacement of the website, or redirection to malicious sites.
    - If an administrative user is targeted, it could lead to account takeover and further compromise of the application and server.

- Vulnerability rank: High

- Currently implemented mitigations:
    - Django's automatic HTML escaping for template variables is used to prevent XSS in the HTML content itself.
    - CSRF protection is implemented to prevent cross-site request forgery attacks.
    - Checksum verification is used to ensure that component updates are valid and not tampered with.
    - HTML encoding of updated field values to prevent XSS attacks is implemented since v0.36.0, primarily focusing on HTML content.

- Missing mitigations:
    - Input sanitization for HTML attributes is missing. While HTML content is encoded, HTML attributes are not systematically sanitized, allowing for attribute injection.
    - There is no clear mechanism to prevent users from injecting dangerous attributes into the DOM via `unicorn:model`.

- Preconditions:
    - The application must be using `django-unicorn` and have components with input fields that use `unicorn:model`.
    - An attacker needs to be able to interact with an input field that uses `unicorn:model` and influence the data that is sent to the server.

- Source code analysis:
    1. In `django_unicorn/components/unicorn_template_response.py`, the `UnicornTemplateResponse.render` method is responsible for rendering the component and updating the DOM.
    2. The server-rendered HTML is parsed using BeautifulSoup (`soup = BeautifulSoup(content, features="html.parser")`).
    3. The relevant part of the DOM is updated using morphdom library based on the HTML returned from the server.
    4. The `morphdom` library efficiently updates the DOM by diffing and patching the new HTML into the existing DOM. However, it does not sanitize HTML attributes.
    5. When the server returns HTML with malicious attributes injected by the attacker via `unicorn:model`, `morphdom` directly applies these attributes to the DOM elements.
    6. For example, if a component template contains `<input unicorn:model="name" type="text" id="text" />` and the attacker manages to inject `" onmouseover="alert('XSS')"`, when the component is updated and the `name` value is reflected back, the resulting HTML might become `<input unicorn:model="name" type="text" id="text"  onmouseover="alert('XSS')" value="malicious input">`.
    7. `morphdom` will apply this attribute directly to the input element, leading to XSS when a user hovers over the input field.
    8. The fix in v0.36.0 (changelog.md) and v0.36.1 ("More complete handling to prevent XSS attacks.") primarily addresses HTML encoding of content, but does not fully mitigate HTML attribute injection vulnerabilities, as attribute sanitization is not implemented in `morphdom` or within the component update logic in `django-unicorn\views\__init__.py`. Review of `django-unicorn\tests\views\test_process_component_request.py` confirms that while HTML content is encoded, attributes are not treated with the same sanitization.

- Security test case:
    1. Create a Django Unicorn component with an input field bound to a component property using `unicorn:model`, e.g., `name`.
    2. Render a page that includes this component.
    3. In the input field, enter a value that includes a malicious HTML attribute, such as `"/><img src=x onerror=alert('XSS')>`.
    4. Trigger an update to the component. This could be done by typing in another input field with `unicorn:model` (if lazy or defer modifier is not used on the vulnerable field), or by clicking a button with `unicorn:click`.
    5. Observe that the injected attribute is now part of the DOM element in the browser's developer tools.
    6. In this specific example `"/><img src=x onerror=alert('XSS')>` may not trigger alert, but attributes like `onmouseover="alert('XSS')"` or `onload="javascript:alert('XSS')"` in img tag may execute javascript.
    7. To verify the XSS, try injecting an `onmouseover` attribute in the input field like this: `test" onmouseover="alert('XSS')"`
    8. Hover over the input field. If a JavaScript alert box appears, the XSS vulnerability is confirmed.
