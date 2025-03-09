# Vulnerabilities in Django-Unicorn

## Unauthorized Method Execution

- **Description**: Django-Unicorn allows any public method on a component to be called via AJAX requests, even if the method is not explicitly exposed as an action in the component's template. This can lead to unauthorized access to sensitive functionalities or data manipulation.

- **Impact**: An attacker can execute any public method defined in a component class, which may include methods that perform sensitive operations (like data deletion) or expose sensitive data, regardless of whether those methods were intended to be called from the client-side or not. This significantly expands the attack surface and may bypass business logic protections implemented in the UI.

- **Vulnerability Rank**: High

- **Currently Implemented Mitigations**: The framework checks that the method exists on the component and uses Django's CSRF protection to prevent cross-site requests. Additionally, requests must have a valid checksum to be processed.

- **Missing Mitigations**: The framework doesn't validate whether a method should be callable via AJAX. A proper mitigation would be to implement an "allowlist" approach, where methods are only callable via AJAX if they're explicitly marked as such.

- **Preconditions**:
  - The attacker needs to be authenticated on the site to get a valid CSRF token
  - They need to know the component's name/ID and the names of methods on the component
  - The methods they want to call must be public (not prefixed with underscore)

- **Source Code Analysis**:
  When Django-Unicorn receives an AJAX request to call a method, it processes the request without validating if the method should be callable from the client. The flow is:

  1. The framework extracts the method name from the request using `parse_call_method_name` from `django_unicorn/call_method_parser.py`
  2. It verifies the method exists using `hasattr(component, method_name)`
  3. It uses `getattr(component, method_name)` to get the method
  4. It calls the method without any verification that the method was meant to be exposed

  Looking at example components like `WizardView` in `example/unicorn/components/wizard/wizard.py`, we can see methods (`next`, `previous`, `finish`, `start`) that could be called directly via AJAX even if they're not explicitly exposed in a template.

  The `parse_call_method_name` function in `call_method_parser.py` parses a method call into a method name, arguments, and keyword arguments, but doesn't validate whether the method should be callable - it simply handles parsing the method call.

  Another concerning aspect is that when a method has a parameter with a Django model type hint, the framework automatically fetches the object with the provided ID using `DbModel.objects.get(pk=value)`. This could potentially allow an attacker to access database objects they shouldn't have permission to view.

- **Security Test Case**:

  1. Create a component with both intended public methods and sensitive methods:

  ```python
  # sensitive_component.py
  from django_unicorn.components import UnicornView

  class SensitiveComponentView(UnicornView):
      access_count = 0

      def public_method(self):
          # This method is meant to be called via the UI
          return "Public method called"

      def delete_all_data(self):
          # This method performs a sensitive operation but isn't exposed in the UI
          return "All data deleted"

      def get_sensitive_data(self):
          # This method returns sensitive information but isn't exposed in the UI
          self.access_count += 1
          return "SSN: 123-45-6789, Credit Card: 4111-1111-1111-1111"
  ```

  2. Create a template that only exposes the public method:

  ```html
  <!-- sensitive-component.html -->
  <div>
    <button unicorn:click="public_method">Call Public Method</button>
  </div>
  ```

  3. An attacker can craft a request to directly call the sensitive methods:

  ```javascript
  // Perform this in the browser console on a page that includes the component
  fetch('/unicorn/message/app.components.sensitive_component.SensitiveComponentView', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]').value,
    },
    body: JSON.stringify({
      id: 'sensitive-component',
      actionQueue: [
        {
          type: 'callMethod',
          payload: {
            name: 'get_sensitive_data',
            args: []
          }
        }
      ],
      data: {},
      checksum: '...',  // Valid checksum would be needed
      epoch: Date.now()
    })
  })
  .then(response => response.json())
  .then(data => console.log(data));
  ```

  4. The sensitive method will execute and return the sensitive data, despite not being exposed in the UI, potentially leading to data exposure or unauthorized operations.
