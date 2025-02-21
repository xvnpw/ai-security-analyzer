## Vulnerability List

### 1) Arbitrary Python Module Import Leading to Remote Code Execution

**Vulnerability name**
Arbitrary Python Module Import Leading to Remote Code Execution

**Description**
1. An external attacker can cause `django-unicorn` to dynamically import Python modules based on user-supplied input.
2. Specifically, in [`django_unicorn\components\unicorn_view.py`](../django-unicorn/django-unicorn/components/unicorn_view.py), the `create()` method attempts to locate a “component” class by concatenating `component_name` with values from the Django `APPS` list and then runs `importlib.import_module` on it.
3. There is no strong validation or whitelisting of the `component_name` beyond some simple string replacements; an attacker who can manipulate that input could craft a path referencing unauthorized modules.
4. If an attacker places a malicious Python module in a location that this dynamic-import path can reach (for example, within one of the Django “apps” or `components` directories allowed by `django-unicorn`), they can force the server to load and run that malicious code.
5. This leads to a full remote code execution scenario if the attacker can upload or otherwise cause malicious code to exist in the import path.

**Impact**
- **Complete compromise of the server**: The attacker can run arbitrary Python code in the context of the Django application.
- Potential exfiltration of sensitive data, server escalation, or pivot to other services if the Python process runs under a privileged account.

**Vulnerability rank**
**critical**

**Currently implemented mitigations**
- The code does some partial normalization of the `component_name` (e.g., rejecting certain characters like dashes or dots). However, this is not a true security measure, as there is no strict module whitelist or denylist.

**Missing mitigations**
- Strict whitelisting of allowed component names or an explicit registry-based loading of valid components.
- Server-side enforcement that only certain modules can be imported; all user input for `component_name` must be ignored or validated against a known-safe list.
- Removing the dynamic import approach entirely or unifying components at startup time.

**Preconditions**
- The attacker can influence or fully set the `component_name` parameter in a template or request.
- The environment has at least one untrusted or unvalidated Python module in the import path (or the attacker can place/replace one).

**Source code analysis**
- In `unicorn_view.py`, `UnicornView.create()`, the relevant lines:

  ```python
  component_class = _get_component_class(module_name, class_name)

  def _get_component_class(module_name: str, class_name: str):
      module = importlib.import_module(module_name)  # No strict validation here
      component_class = getattr(module, class_name)
  ```

  An external attacker can set `module_name` indirectly via `component_name` unless the developer secures it.

**Security test case**
1. Create a malicious Python file at `myapp/components/evil_component.py`:
   ```python
   import os

   os.system("echo HACKED > /tmp/pwned.txt")

   class EvilComponentView:
       pass
   ```
2. Deploy it in the same server environment where `django-unicorn` can discover imports.
3. From an untrusted template/request, pass `component_name="evil-component"` (or equivalent) referencing `evil_component.EvilComponentView`.
4. Confirm that the server processes the malicious Python code (e.g., it writes `HACKED` to `/tmp/pwned.txt`).

---

### 2) Insecure Direct Object Reference (IDOR) on Model Access

**Vulnerability name**
Insecure Direct Object Reference (IDOR) on Model Access

**Description**
1. The `django-unicorn` library automatically loads Django models by `pk` (or other fields) when action method parameters are typed as a Django Model.
2. For example, if a component method is declared as `def delete_book(self, book: Book):`, `django-unicorn` will parse incoming requests (e.g., `unicorn:click="delete_book(123)"`) and silently fetch the `Book(pk=123)` object.
3. By default, there is no permission or ownership check; an attacker can provide arbitrary IDs to read or modify records.
4. This can lead to unauthorized updates or deletions of database objects.

**Impact**
- Attackers can guess or iterate numeric IDs to view, update, or delete data they should not control.
- Potential for severe data corruption or leakage.

**Vulnerability rank**
**high**

**Currently implemented mitigations**
- None are built into `django-unicorn`. The library’s documentation suggests standard Django forms/validations, but leaves it up to the developer to implement checks.

**Missing mitigations**
- Performing explicit permission or ownership checks inside each action method.
- Integrating an authentication/authorization callback in the library itself to verify if the user can access the specified object.

**Preconditions**
- The attacker can guess valid primary keys.
- The application uses typed method arguments, e.g. `def edit_book(self, book: Book):`, allowing `django-unicorn` to auto-fetch books by ID.

**Source code analysis**
- This behavior is found in `typer.py` (the `create_queryset` logic) and used in many example methods:

  ```python
  def set_color(self, color: Color):
      ...
  def delete(self, pk: Book=None):
      pk.delete()  # No permission checks
  ```

**Security test case**
1. Host a `django-unicorn` component referencing a model in a method signature, e.g. `def edit_book(self, book: Book):`.
2. Note the code will directly load the `Book` object by the provided ID.
3. Submit a request calling `edit_book(9999)`, referencing a record the user is not authorized to access.
4. Confirm that the action is performed with no error, demonstrating IDOR.

---

### 3) Cross-Site Scripting (XSS) via `Meta.safe` Fields

**Vulnerability name**
Cross-Site Scripting (XSS) via `Meta.safe` Fields

**Description**
1. When a component’s `Meta.safe` list designates certain fields as “safe,” `django-unicorn` uses `mark_safe()` for those fields.
2. If an attacker controls the contents of one of these “safe” fields, they can insert `<script>` tags or other malicious HTML.
3. The result is a stored or reflected XSS, allowing arbitrary JavaScript to run in victims’ browsers.

**Impact**
- **High-impact XSS**: Attackers can hijack user sessions, exfiltrate data, or impersonate victims inside the application.

**Vulnerability rank**
**high**

**Currently implemented mitigations**
- None. `mark_safe()` is applied unconditionally to any field listed in `Meta.safe`.

**Missing mitigations**
- Avoid adding user-controlled fields to `Meta.safe`.
- For user-generated HTML, apply robust sanitization on the server side.
- Exclude or strictly validate any content that might contain `<script>` or other malicious tags from being rendered unescaped.

**Preconditions**
- The developer configures a field in `Meta.safe` that can be set from external input.
- An attacker can manipulate that field’s value.

**Source code analysis**
- In [`django_unicorn\views\__init__.py`](../django-unicorn/django-unicorn/views/__init__.py):

  ```python
  for field_name in safe_fields:
      value = getattr(component, field_name)
      if isinstance(value, str):
          setattr(component, field_name, mark_safe(value))
  ```

  Any string in a declared “safe” field is rendered unescaped.

**Security test case**
1. Create a component with a safe field:
   ```python
   from django_unicorn.components import UnicornView

   class TestSafeView(UnicornView):
       field_for_attack = ""

       class Meta:
           safe = ("field_for_attack",)
   ```
2. From untrusted input, set `field_for_attack` to `<script>alert("xss")</script>`.
3. Confirm that the `<script>` executes when the page re-renders, validating XSS.
