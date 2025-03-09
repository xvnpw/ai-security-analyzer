- Vulnerability Name: Cross-Site Scripting (XSS) in component properties rendering
- Description:
  - An attacker can inject malicious JavaScript code into a component property.
  - When the component is rendered in a Django template, the injected JavaScript code is executed in the user's browser because the component property is rendered without proper sanitization by default.
  - Step 1: An attacker crafts a malicious input containing JavaScript code, for example: `<img src=x onerror=alert("XSS")>`.
  - Step 2: This malicious input is passed as a value to a component property, either through URL parameters, form input, or other data sources that populate component properties. For example, a URL like `/component-view/?user_input=<img src=x onerror=alert("XSS")>`.
  - Step 3: The Django application renders the template containing the vulnerable component, passing the user-controlled input to the component.
  - Step 4: The django-unicorn library renders the component, including the unsanitized malicious JavaScript code from the component property directly into the HTML template, especially if the `safe` meta option is used for this property.
  - Step 5: When a user views the page in their browser, the malicious JavaScript code is executed, in this example, an alert box with "XSS" will pop up.
- Impact:
  - Successful exploitation can lead to Cross-Site Scripting (XSS).
  - An attacker can execute arbitrary JavaScript code in the victim's browser, potentially leading to:
    - Account hijacking
    - Session theft
    - Defacement of the website
    - Redirection to malicious sites
    - Data theft
    - Installation of malware
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - The documentation mentions a `safe` Meta option in `views.md`: "By default, `unicorn` HTML encodes updated field values to prevent XSS attacks. You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple." This indicates that HTML encoding is enabled by default to prevent XSS, but developers can bypass it using `safe`.
  - The `django_unicorn.utils.sanitize_html` function exists, which is used to sanitize HTML. However, source code analysis shows it's primarily used for sanitizing JSON init data, not for general component property rendering in templates.
- Missing Mitigations:
  - While HTML encoding is the default behavior, it relies on developers to not use the `safe` option when rendering user-provided content if they want default HTML encoding.
  - There is no clear and prominent documentation warning developers about the risks of using the `safe` option and when it is appropriate to use it. Developers might unknowingly introduce XSS vulnerabilities by using `safe` without proper sanitization.
  - Input sanitization is not enforced by default for all component properties rendered in templates. The library depends on Django's template auto-escaping for default protection, which is bypassed by the `safe` option.
  - The `safe` option should ideally be used only when developers explicitly need to render HTML content from trusted sources and are fully aware of the security implications. A clearer mechanism and stronger warnings are needed.
- Preconditions:
  - The application must be using django-unicorn to render dynamic components.
  - User input must be able to influence component properties that are rendered in templates.
  - The developer must mark a component property as `safe` in the `Meta` class and not sanitize user-provided content that populates this property.
- Source Code Analysis:
  - Analyzing `django_unicorn/components/unicorn_view.py`, the `UnicornView` class handles component rendering. The `render` method in `UnicornView` delegates rendering to `UnicornTemplateResponse`.
  - `UnicornTemplateResponse.render` uses `BeautifulSoup` for template processing but primarily for morphing and updating parts of the DOM, not for sanitization of component properties before rendering them into the template.
  - The `_desoupify` method in `UnicornTemplateResponse` serializes the BeautifulSoup object back to HTML, but it uses `formatter=UnsortedAttributes()`, which is for HTML formatting and attribute ordering, not for sanitization.
  - The `django_unicorn.utils.sanitize_html` function is used in `UnicornTemplateResponse.render`, but only to sanitize the JSON init data when `init_js` is True:
    ```python
    json_tag.string = sanitize_html(init)
    ```
    This confirms that `sanitize_html` is applied to the component's initialization data (which is JSON) and not to the dynamic component properties that are directly rendered in the template using Django's template language (e.g., `{{ component.property }}`).
  - The default HTML encoding mentioned in the documentation relies on Django's template engine's auto-escaping feature. Django automatically escapes HTML characters when rendering variables in templates, which is a general Django security feature to prevent basic XSS. However, this auto-escaping is explicitly bypassed when the `safe` filter or the `safe` meta option in django-unicorn is used.
  - The `safe` Meta option, as defined in the component, allows developers to explicitly mark certain component properties as safe from HTML encoding. This behavior is confirmed by the code structure and documentation. The file `tests/views/test_process_component_request.py` includes tests `test_html_entities_encoded` and `test_safe_html_entities_not_encoded` that demonstrate how HTML entities are encoded by default and not encoded when `safe` is used.
  - The vulnerability arises when developers use the `safe` option for component properties that are populated with user-controlled input without performing proper sanitization of that input. Django-unicorn library itself does not provide or enforce any automatic sanitization for properties marked as `safe`. It trusts the developer to handle sanitization when they choose to use the `safe` option.
  - In `django_unicorn/views/action_parsers/sync_input.py`, the `handle` function and `set_property_value` function are responsible for updating component properties based on user input from `syncInput` actions. Reviewing `django_unicorn/views/action_parsers/utils.py`, the `set_property_value` function is further used to set properties. This function focuses on setting the property value and handling type casting but does not include any HTML sanitization logic. The updated value is directly set to the component property, and during the next render cycle, if this property is used in the template with `safe` option, it will be rendered without sanitization. The file `tests/views/utils/test_set_property_from_data.py` provides tests for `set_property_from_data` utility, confirming that data from requests can directly update component properties, highlighting the path for user-controlled data to reach component properties without sanitization.
- Security Test Case:
  - Step 1: Create a django-unicorn component named `xss-safe-test` that displays a property called `user_input` in its template and mark it as `safe` in the `Meta` class.
  ```python
  # components/xss_safe_test.py
  from django_unicorn.components import UnicornView

  class XssSafeTestView(UnicornView):
      user_input = ""

      class Meta:
          safe = ("user_input",)
  ```
  ```html
  <!-- templates/unicorn/xss-safe-test.html -->
  <div>
      {{ user_input }}
  </div>
  ```
  - Step 2: Create a Django view and template to render the `xss-safe-test` component. This view will pass user-controlled input from the URL query parameter `user_input` to the component.
  ```python
  # views.py
  from django.shortcuts import render

  def xss_safe_test_view(request):
      user_controlled_input = request.GET.get('user_input', '') # Simulate user input from URL
      return render(request, 'xss_safe_test_template.html', {'user_controlled_input': user_controlled_input})
  ```
  ```html
  <!-- templates/xss_safe_test_template.html -->
  {% load unicorn %}
  <html>
  <head>
      {% unicorn_scripts %}
  </head>
  <body>
      {% csrf_token %}
      {% unicorn 'xss-safe-test' user_input=user_controlled_input %}
  </body>
  </html>
  ```
  - Step 3: Start the Django development server and access the `xss_safe_test_view` URL with a malicious payload in the `user_input` query parameter. For example: `/xss_safe_test/?user_input=<img src=x onerror=alert("XSS_SAFE")>`
  - Step 4: Observe the browser's behavior. Check if the JavaScript code `alert("XSS_SAFE")` is executed.
  - Expected Result: If the `alert("XSS_SAFE")` box appears when accessing the URL with the malicious payload, it confirms the Cross-Site Scripting (XSS) vulnerability. This result indicates that when the `safe` option is used for a component property and the developer does not sanitize user input, it leads to XSS. This test case directly demonstrates the risk of using the `safe` option without proper input handling, as highlighted in the vulnerability description.
