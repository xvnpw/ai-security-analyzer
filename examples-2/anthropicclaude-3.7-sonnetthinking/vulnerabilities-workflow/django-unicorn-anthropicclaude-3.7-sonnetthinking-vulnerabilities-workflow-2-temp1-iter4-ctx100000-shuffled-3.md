# VULNERABILITIES

## Cross-Site Scripting (XSS) in Components with Safe Fields

**Description:**
Django-Unicorn provides a mechanism to mark component fields as "safe" using the `Meta.safe` tuple, which prevents HTML encoding of those fields when rendered in templates. An attacker can exploit this feature by injecting malicious JavaScript into a field marked as "safe" if they can control the content of that field.

Step by step attack:
1. Identify a component that uses `Meta.safe = ("field_name",)` to mark a field as safe from HTML encoding
2. Find a way to set the value of this field (typically through a form input bound with `unicorn:model`)
3. Input malicious JavaScript payload like `<script>alert(document.cookie)</script>` into the form field
4. When the component re-renders, the unescaped JavaScript will execute in the victim's browser

**Impact:**
Critical - This vulnerability allows attackers to execute arbitrary JavaScript in the context of victims' browsers, potentially leading to session hijacking, credential theft, or arbitrary actions performed on behalf of the victim.

**Currently implemented mitigations:**
The framework does include a warning in the documentation about this risk. By default, all component fields are HTML escaped to prevent XSS attacks. The unsafe behavior requires explicit opt-in by developers through the `Meta.safe` attribute.

**Missing mitigations:**
- No runtime warnings when a field is marked as safe
- No sanitization of user input even when marked as safe
- No automatic content security policy implementation

**Preconditions:**
1. A component must have at least one field marked as "safe" in its Meta class
2. An attacker must be able to control the content of this field
3. The unsafe field must be rendered in the template

**Source code analysis:**
The vulnerability exists in `django_unicorn/views/__init__.py` where fields marked as "safe" are processed:

```python
# Mark safe attributes as such before rendering
for field_name in safe_fields:
    value = getattr(component, field_name)
    if isinstance(value, str):
        setattr(component, field_name, mark_safe(value))  # noqa: S308
```

This code explicitly marks the field content as safe using Django's `mark_safe()` function, which instructs Django's template engine not to escape the content. If an attacker can control this content, they can inject malicious JavaScript.

In `test_process_component_request.py`, there's a test demonstrating this behavior:

```python
def test_safe_html_entities_not_encoded(client):
    data = {"hello": "test"}
    action_queue = [
        {
            "payload": {"name": "hello", "value": "<b>test1</b>"},
            "type": "syncInput",
        }
    ]
    response = post_and_get_response(
        client,
        url="/message/tests.views.test_process_component_request.FakeComponentSafe",
        data=data,
        action_queue=action_queue,
    )

    assert not response["errors"]
    assert response["data"].get("hello") == "<b>test1</b>"
    assert "<b>test1</b>" in response["dom"]
```

This test shows that when a field is marked as safe, HTML tags aren't encoded and are rendered as-is in the DOM.

**Security test case:**
1. Create a Django-Unicorn component with a field marked as "safe":
```python
class VulnerableComponent(UnicornView):
    content = "<p>Initial content</p>"

    class Meta:
        safe = ("content",)
```

2. Create a template that uses this component:
```html
<div>
    <input unicorn:model="content" type="text" id="content" />
    <div>{{ content }}</div>
</div>
```

3. As an attacker, access the page with this component
4. Enter malicious payload into the input: `<img src="x" onerror="alert(document.cookie)">`
5. Observe that the JavaScript executes and displays the cookie
6. Demonstrate that with a properly crafted payload, an attacker could exfiltrate sensitive data

## Unauthorized Method Execution Through Component Actions

**Description:**
Django-Unicorn doesn't restrict which methods can be called on components through the frontend. Any public method on a component can be called via AJAX requests, which can lead to unauthorized actions if the component methods don't implement proper authorization checks.

Step by step attack:
1. Identify a Django-Unicorn component with sensitive methods
2. Craft an AJAX request to the component's message endpoint
3. Include a `callMethod` action in the request with the sensitive method name
4. Send the request and have the method execute without proper authorization

**Impact:**
High - This vulnerability allows attackers to invoke any public method on a component, potentially leading to unauthorized data access, data manipulation, or privilege escalation if the methods don't implement proper authorization checks.

**Currently implemented mitigations:**
Django-Unicorn uses Django's CSRF protection to prevent cross-site request forgery attacks. Without a valid CSRF token, attackers cannot make successful requests to call methods.

**Missing mitigations:**
- No method whitelisting mechanism to restrict callable methods
- No automatic authorization checks for component methods
- No documentation emphasizing the need for authorization checks

**Preconditions:**
1. A component must have methods that perform sensitive operations
2. These methods must lack proper authorization checks
3. The attacker must be able to obtain a valid CSRF token (usually by being authenticated in the application)

**Source code analysis:**
In `django_unicorn/views/action_parsers/call_method.py`, the framework processes method calls from the frontend:

```python
def handle(component_request: ComponentRequest, component: UnicornView, payload: Dict):
    method_name = payload.get("name")
    # ... code to parse arguments ...
    _call_method_name(component, method_name, args=args, kwargs=kwargs)
```

There's no validation of which methods can be called - any method on the component can be invoked if it exists. The code in `test_call_method.py` demonstrates that any method can be called:

```python
def test_message_call_method(client):
    data = {"method_count": 0}
    body = _post_to_component(client, "test_method", data=data)

    assert body["data"].get("method_count") == 1
```

This shows that arbitrary methods can be called through the frontend interface.

**Security test case:**
1. Create a Django-Unicorn component with a sensitive method:
```python
class AdminComponent(UnicornView):
    def delete_user(self, user_id):
        # Delete user without authorization check
        User.objects.filter(id=user_id).delete()
        return f"User {user_id} deleted"
```

2. Create a template that uses this component (without exposing the sensitive method in the UI):
```html
<div>
    <h1>Admin Dashboard</h1>
    <!-- No UI element calls delete_user -->
</div>
```

3. As an attacker, craft an AJAX request to call the sensitive method:
```
POST /unicorn/message/path.to.AdminComponent
{
  "actionQueue": [
    {
      "type": "callMethod",
      "payload": {
        "name": "delete_user",
        "args": [1]
      }
    }
  ],
  "data": {},
  "checksum": "valid_checksum",
  "id": "component_id",
  "epoch": timestamp
}
```

4. Include a valid CSRF token in the request
5. Send the request and observe that the method executes, deleting the user without proper authorization
