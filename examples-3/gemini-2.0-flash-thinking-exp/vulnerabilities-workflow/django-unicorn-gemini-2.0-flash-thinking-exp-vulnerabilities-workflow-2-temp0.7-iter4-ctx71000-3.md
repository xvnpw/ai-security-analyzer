### Vulnerability List:

- **Vulnerability Name:**  Potential Cross-Site Scripting (XSS) in Template Rendering due to explicit `safe` usage without input sanitization

- **Description:**
    1. A threat actor can inject malicious JavaScript code into user-provided data.
    2. If a Django developer uses the `safe` filter in a Django template when rendering output from a Django Unicorn component, OR uses `Meta.safe` in the component view to disable automatic HTML escaping for specific variables.
    3. And if this user-provided data is then rendered using this `safe` output without proper sanitization, the malicious script will be executed in the victim's browser.
    4. Django templates by default escape HTML, which is a built-in mitigation against XSS. However, Django Unicorn provides mechanisms to bypass this default escaping using `safe` filter in templates or `Meta.safe` setting in components, offering flexibility but also potential security risks if misused.
    5. The `changelog.md` file highlights the security fix in version 0.36.0 (CVE-2021-42053) that made HTML encoding the default behavior, and explicitly mentions that `safe` is required to opt-in to the previous behavior, reinforcing the understanding that `safe` usage needs careful consideration.
    6. Documentation in `views.md` for `Meta.safe` option clarifies that "By default, `unicorn` HTML encodes updated field values to prevent XSS attacks. You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple.", confirming the default safe behavior and the explicit opt-in for unsafe rendering.
    7. Tests like `test_safe_html_entities_not_encoded` in `test_process_component_request.py` directly demonstrate that when `Meta.safe` is used, HTML content is rendered without encoding, which can be exploited for XSS if the data source is not trusted.

- **Impact:**
    - Cross-Site Scripting (XSS) allows an attacker to execute arbitrary JavaScript code in the victim's browser.
    - This can lead to serious security breaches, including session hijacking, cookie theft, website defacement, redirection to malicious sites, or performing unauthorized actions on behalf of the user, potentially compromising user data and trust in the application.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - Django Unicorn, by default, mitigates XSS by HTML-encoding output, as documented in `changelog.md` (version 0.36.0) and `docs/source/views.md`. This default behavior significantly reduces the risk of XSS.
    - The framework forces developers to explicitly use `safe` filter in templates or `Meta.safe` in component views to disable HTML escaping for specific variables, making it a conscious decision to bypass the default protection.
    - Tests in `test_process_component_request.py`, such as `test_html_entities_encoded`, confirm that default encoding is in place and working as expected.

- **Missing Mitigations:**
    - While default escaping is a strong mitigation, the documentation could include a more prominent and explicit security warning about the dangers of using `safe` and the critical need for input sanitization to prevent XSS vulnerabilities when `safe` is employed.
    - There are no documented automated checks or linters within Django Unicorn itself to detect potentially unsafe usage of `safe`. Developers rely on manual code reviews and security best practices to avoid introducing XSS vulnerabilities.
    - Content Security Policy (CSP) is not mentioned in the documentation as a recommended security measure. While CSP is a general web security practice and not specific to Django Unicorn, recommending its use could provide an additional layer of defense against XSS attacks, especially when combined with Django Unicorn's default escaping and developer awareness.

- **Preconditions:**
    1. A Django developer must intentionally bypass the default HTML escaping by either using the `safe` filter in a Django template (e.g., `{{ variable|safe }}`) or by including the corresponding field name in the `safe` tuple within the component's `Meta` class (e.g., `Meta.safe = ("field_name",)`).
    2. User-provided data must be directly bound to a component's variable that is configured to be rendered as `safe`.
    3. A threat actor must have the ability to inject malicious JavaScript code into this user-provided data. Common injection points include form fields, URL parameters, or any other input mechanism that allows the attacker to control the data rendered by the component.

- **Source Code Analysis:**
    - The primary mitigation against XSS is the default HTML encoding applied during template rendering within Django Unicorn. This is implicitly handled by Django's template engine and explicitly configured in Django Unicorn to be the default.
    - The vulnerability is introduced when developers explicitly disable this default escaping mechanism using the `safe` filter or `Meta.safe`.
    - Analyzing `django_unicorn/views/__init__.py`, specifically the `_process_component_request` function, reveals the code responsible for handling the `Meta.safe` option:
    ```python
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
    - This code snippet first checks if the component's `Meta` class has a `safe` attribute. If it does, and if `safe` is a sequence (like a tuple or list), it iterates through each `field_name` in `Meta.safe`.
    - For each `field_name`, it verifies if it corresponds to an attribute of the component. If it is a valid attribute, the code retrieves the attribute's value using `getattr(component, field_name)`.
    - Crucially, if the retrieved `value` is a string, it is then marked as safe for HTML output using Django's `mark_safe()` function. This function tells Django's template engine *not* to escape this string when rendering it in a template.
    - Consequently, if a component renders a variable that is listed in `Meta.safe`, and if the value of this variable originates from user input and contains malicious JavaScript, the `mark_safe()` function will ensure that this script is rendered directly into the HTML output without escaping, leading to a potential XSS vulnerability.
    - The test `test_safe_html_entities_not_encoded` in `django_unicorn/tests/views/test_process_component_request.py` directly tests and confirms this behavior. It shows that when `Meta.safe` is configured for a component, HTML entities in the specified field are not encoded in the rendered output, which is necessary for scenarios where unescaped HTML is intentionally required but creates an XSS risk if user input is not properly sanitized before being marked as safe.

- **Security Test Case:**
    1. **Setup:** Create a Django project with a Django Unicorn component named `XSSComponent`.
    2. **Component Definition:** Define `XSSComponent` with a `message` attribute and configure `Meta.safe` to include `message`:
    ```python
    # components/xss_component.py
    from django_unicorn.components import UnicornView

    class XSSComponentView(UnicornView):
        template_name = "unicorn/xss_component.html"
        message = ""

        class Meta:
            safe = ("message",)
    ```
    3. **Template Creation:** Create a template `unicorn/xss_component.html` that renders the `message` variable:
    ```html
    {# templates/unicorn/xss_component.html #}
    <div>
        <span id="xss-output">{{ message }}</span>
    </div>
    ```
    4. **View and URL Configuration:** Create a Django view to render the component and configure the URL:
    ```python
    # views.py
    from django.shortcuts import render
    from .components.xss_component import XSSComponentView

    def xss_test_view(request):
        component = XSSComponentView(component_name="xss-component")
        return render(request, 'xss_test_template.html', {'unicorn': component.render()})

    # urls.py
    from django.urls import path
    from . import views

    urlpatterns = [
        path('xss-test/', views.xss_test_view, name='xss-test'),
        path("", include("django_unicorn.urls")),
    ]
    ```
    5. **Test Template:** Create `xss_test_template.html` to include the Unicorn component and a form to set the `message`:
    ```html
    {# templates/xss_test_template.html #}
    {% load unicorn %}
    <!DOCTYPE html>
    <html>
    <head>
        <title>XSS Test</title>
        {% unicorn_scripts %}
    </head>
    <body>
        <form id="xssForm" method="post">
            {% csrf_token %}
            <input type="text" id="messageInput" name="message" value="">
            <button type="submit">Set Message</button>
        </form>

        {% unicorn 'xss-component' %}

        <script>
            document.getElementById('xssForm').addEventListener('submit', function(event) {
                event.preventDefault();
                const message = document.getElementById('messageInput').value;
                Unicorn.getComponent('xss-component').set({'message': message}).then(() => {
                    // Component updated
                });
            });
        </script>
    </body>
    </html>
    ```
    6. **Execute Exploit:**
        - Access `/xss-test/` in a browser.
        - In the input field, enter the following malicious payload: `<script>alert("XSS Vulnerability");</script>`.
        - Click "Set Message".
    7. **Verify Vulnerability:** Observe that an alert box appears with the message "XSS Vulnerability". This confirms that the JavaScript code was executed because the `message` variable, marked as `safe`, rendered the script without escaping.
    8. **Test Mitigation (Default Escape):**
        - Modify `XSSComponentView` by removing `"message",` from `Meta.safe`.
        ```python
        class Meta:
            safe = () # or remove Meta.safe entirely
        ```
        - Repeat steps 6 and 7.
        - Observe that the alert box does *not* appear. Instead, the raw JavaScript payload `<script>alert("XSS Vulnerability");</script>` is rendered as text in the `span#xss-output` element. This demonstrates that the default HTML escaping is now active and prevents the XSS attack.
    9. **Expected Outcome:** The alert box appearing in step 7 confirms the XSS vulnerability when `safe` is used without sanitization. The absence of the alert box and the escaped output in step 8 confirms the default mitigation is working and that the vulnerability is directly related to the explicit use of `safe`.
