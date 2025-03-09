# Vulnerabilities in Django Unicorn

## 1. Cross-Site Scripting (XSS) through `Meta.safe` attribute

- **Vulnerability name**: Cross-Site Scripting (XSS) through `Meta.safe` attribute

- **Description**: Django Unicorn allows developers to mark specific component fields as "safe" using the `Meta.safe` attribute, which bypasses the HTML encoding that normally prevents XSS attacks. If a field marked as "safe" contains user-supplied input, this could lead to Cross-Site Scripting vulnerabilities.

  To trigger this vulnerability:
  1. Create a component with a field that accepts user input
  2. Mark that field as "safe" in the component's Meta class
  3. Render the field value in a template without additional sanitization
  4. Submit malicious JavaScript code through the user input
  5. When the component rerenders, the JavaScript will execute in the user's browser

- **Impact**: This vulnerability could allow attackers to execute arbitrary JavaScript in users' browsers, potentially leading to session hijacking, credential theft, data exfiltration, or other malicious actions performed in the context of the victim's browser session.

- **Vulnerability rank**: High

- **Currently implemented mitigations**: Django Unicorn does HTML encode field values by default to prevent XSS attacks, as confirmed in the `test_html_entities_encoded` test which verifies that HTML tags get encoded as entities. This was implemented as a security fix in v0.36.0 for CVE-2021-42053. However, the framework still allows developers to bypass this protection through the `Meta.safe` attribute as seen in `test_safe_html_entities_not_encoded`.

- **Missing mitigations**:
  1. Lack of clear security warnings in documentation about the risks of using `Meta.safe`
  2. No runtime warnings when user-editable fields are marked as safe
  3. No alternative safe rendering method that allows HTML but still sanitizes harmful scripts
  4. No static analysis tools to detect potentially unsafe use of the attribute

- **Preconditions**:
  1. A Django Unicorn component must exist with a field that contains user-supplied input
  2. The field must be marked as "safe" in the component's Meta class
  3. The field value must be rendered in a template

- **Source code analysis**:
  The vulnerability is rooted in how Django Unicorn handles the `Meta.safe` attribute. In `django_unicorn/views/__init__.py`, we can see how safe fields are processed:

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

  The code applies Django's `mark_safe` function to fields specified in `Meta.safe`, which explicitly tells Django not to escape HTML entities when rendering. This is confirmed by the test `test_safe_html_entities_not_encoded` which verifies that HTML in safe fields passes through unencoded.

  When a field is marked as "safe", it is rendered without HTML encoding. If this field contains user input that includes malicious JavaScript like `<script>alert('XSS')</script>`, the script would be executed when the component is rendered.

- **Security test case**:
  1. Create a component that accepts user input:
  ```python
  # xss_test.py
  from django_unicorn.components import UnicornView

  class XssTestView(UnicornView):
      user_input = ""

      class Meta:
          safe = ("user_input", )

      def set_input(self, value):
          self.user_input = value
  ```

  2. Create a template that renders the user input:
  ```html
  <!-- xss-test.html -->
  <div>
    <input unicorn:model="user_input" type="text" />
    <button unicorn:click="set_input(user_input)">Set Input</button>
    <div>{{ user_input }}</div>
  </div>
  ```

  3. Attempt to inject malicious JavaScript:
     - Enter `<script>alert('XSS Attack')</script>` into the input field
     - Click the "Set Input" button
     - If vulnerable, an alert dialog with "XSS Attack" will appear
     - If properly mitigated, the script tags would be displayed as text and not executed
