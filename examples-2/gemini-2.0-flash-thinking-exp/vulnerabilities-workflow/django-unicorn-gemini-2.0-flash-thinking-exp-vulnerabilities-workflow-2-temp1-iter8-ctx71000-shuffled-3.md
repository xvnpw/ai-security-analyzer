- Vulnerability name: Cross-Site Scripting (XSS) through `safe` usage

- Description:
  1. A developer uses `django-unicorn` to create a component that renders user-provided content or component properties.
  2. To bypass the default Django auto-escaping, the developer uses the `safe` template filter in the component's HTML template or defines `safe` fields in the component's `Meta` class.
  3. An attacker injects malicious Javascript code as user input or crafts a component property containing malicious Javascript code.
  4. When the component is rendered, the `safe` filter or `Meta.safe` directive prevents Django from escaping the malicious Javascript code.
  5. The malicious Javascript code is executed in the user's browser when the component is rendered or updated, leading to XSS.

- Impact:
  Successful exploitation of this vulnerability can allow an attacker to execute arbitrary Javascript code in the victim's browser. This can lead to:
  - Account hijacking: Stealing session cookies or credentials to impersonate the user.
  - Data theft: Accessing sensitive information, including personal data or application secrets.
  - Defacement: Modifying the content of the web page seen by the user.
  - Redirection: Redirecting the user to a malicious website.
  - Execution of unauthorized actions on behalf of the user.

- Vulnerability rank: High

- Currently implemented mitigations:
  - Django's default auto-escaping: Django templates, by default, automatically escape HTML content to prevent XSS. This is a general Django mitigation that is in place when using django-unicorn templates.
  - CSRF protection: Django Unicorn uses CSRF tokens to protect its AJAX endpoints, which helps prevent CSRF attacks. While not directly mitigating XSS, it is a general security measure for Django applications.

- Missing mitigations:
  - Lack of explicit warnings or guidelines in the documentation against using `safe` filter or `Meta.safe` with user-provided or potentially unsafe content.
  - No built-in mechanism within django-unicorn to automatically sanitize content marked as `safe`.
  - No security-focused linters or checks within the project to detect potentially unsafe usage of `safe`.

- Preconditions:
  - The developer must explicitly use the `safe` template filter or `Meta.safe` in a django-unicorn component.
  - User input or component properties rendered with `safe` must be controllable by the attacker or contain attacker-controlled data.

- Source code analysis:
  - In `docs\source\views.md`, the documentation for `Meta.safe` feature explains how to bypass the default HTML encoding.
  - It states: "By default, `unicorn` HTML encodes updated field values to prevent XSS attacks. You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple."
  - This documentation clearly indicates that `django-unicorn` provides a mechanism to disable XSS protection (`safe`), and it is the developer's responsibility to use it safely.
  - If a developer misuses this feature by applying `safe` to render unsanitized user inputs, they will create an XSS vulnerability.
  - The code itself does not introduce XSS, but it provides the option to bypass default XSS protections, relying on developer vigilance.
  - In `django_unicorn\views\__init__.py`, the `_process_component_request` function iterates through `safe_fields` defined in `Meta.safe` and uses `mark_safe` on the corresponding component attributes before rendering.
    ```python
    # Get set of attributes that should be marked as `safe`
    safe_fields = []
    if hasattr(component, "Meta") and hasattr(component.Meta, "safe"):
        if isinstance(component.Meta.safe, Sequence):
            for field_name in component.Meta.safe:
                if field_name in component._attributes().keys():
                    safe_fields.append(field_name)

    # Mark safe attributes as such before rendering
    for field_name in safe_fields:
        value = getattr(component, field_name)
        if isinstance(value, str):
            setattr(component, field_name, mark_safe(value))  # noqa: S308
    ```
  - This code snippet shows that fields listed in `Meta.safe` are explicitly marked as safe using Django's `mark_safe` utility, which disables auto-escaping for these fields during template rendering.

- Security test case:
  1. Create a django-unicorn component named `xss_safe_test`.
  2. In the component's Python view (`xss_safe_test.py`), define a property `unsafe_content` and a `Meta` class to mark `unsafe_content` as safe:
     ```python
     from django_unicorn.components import UnicornView

     class XssSafeTestView(UnicornView):
         unsafe_content = ""

         class Meta:
             safe = ("unsafe_content",)
     ```
  3. In the component's HTML template (`xss_safe_test.html`), render the `unsafe_content` property:
     ```html
     <div>
         {{ unsafe_content }}
     </div>
     ```
  4. Create a Django view to render a template that includes the `xss_safe_test` component.
  5. Access the page in a browser. The component will be rendered without any XSS vulnerability yet because `unsafe_content` is empty by default.
  6. In the browser's developer tools, use Javascript to modify the component's data directly to inject malicious Javascript. For example, if the component's id is `xss_safe_test-123`, you can execute Javascript like:
     ```javascript
     Unicorn.componentViewModels['xss_safe_test-123'].setModel({'unsafe_content': '<img src=x onerror=alert("XSS Vulnerability")>'});
     ```
  7. Observe that an alert box appears, demonstrating that the Javascript code injected into `unsafe_content` was executed because the content was rendered as `safe` and not escaped.
  8. Alternatively, if `unsafe_content` was bound to a user input using `unicorn:model`, an attacker could input `<img src=x onerror=alert("XSS Vulnerability")>` into the input field, and upon component update, the XSS would be triggered if `unsafe_content` is marked as `safe`.
