### Vulnerability List for django-unicorn Project

- Vulnerability Name: Cross-Site Scripting (XSS) vulnerability due to unsafe HTML attribute injection
- Description:
    1. An attacker can manipulate component's state, specifically string properties, through `unicorn:model` binding.
    2. When the component re-renders, these manipulated string properties are injected into the HTML template.
    3. If the injected string is used as an HTML attribute value without proper escaping, it can lead to XSS.
    4. For example, if a component has a property `name` and the template uses it in an attribute like `<div title="{{ name }}">`, an attacker can set `name` to `"onmouseover=alert('XSS') a="`.
    5. When the component updates, the rendered HTML will become `<div title="onmouseover=alert('XSS') a="></div>`, leading to XSS when the mouse hovers over the div.

- Impact:
    - High
    - Successful exploitation allows an attacker to execute arbitrary JavaScript code in the victim's browser when they interact with the vulnerable component.
    - This can lead to session hijacking, account takeover, defacement, or redirection to malicious websites.

- Vulnerability Rank: high

- Currently Implemented Mitigations:
    - HTML encoding of updated field values is mentioned in changelog and documentation to prevent XSS attacks. However, this encoding is not consistently applied to HTML attributes within the component rendering process. The current sanitization primarily focuses on the content within HTML tags, not attributes.

- Missing Mitigations:
    - The project lacks context-aware output encoding specifically for HTML attributes.
    - It should automatically escape HTML attributes to prevent injection of malicious JavaScript.
    - Implement automatic HTML attribute escaping during component rendering, potentially by leveraging Django's template engine's auto-escaping features more effectively or by using a dedicated HTML attribute escaping function before injecting dynamic values into attributes.

- Preconditions:
    - A Django Unicorn component is used in the application.
    - The component template uses a string property, bound via `unicorn:model`, directly within an HTML attribute (e.g., `title`, `alt`, `style`, event handlers like `onmouseover`, `onclick` etc.).
    - The application code or component template does not manually escape the property value when used in the attribute.

- Source Code Analysis:
    1. **File: `django_unicorn/components/unicorn_template_response.py`**: This file handles the rendering of the component template. While it includes `sanitize_html`, this function is primarily used for sanitizing the entire HTML output, not specifically for context-aware escaping of HTML attributes. The template rendering process within `UnicornTemplateResponse` doesn't explicitly enforce attribute escaping.
    2. **File: `django_unicorn/views/views.py`**: This file processes user interactions and triggers component re-rendering.  The `component.render()` method is called, which eventually uses Django's template engine. Django's template auto-escaping is generally effective for HTML tag content but might not be sufficient for all attribute contexts, especially when dynamic values from component state are directly injected into attributes. The vulnerability arises because the values updated via `unicorn:model` are not specifically escaped for HTML attribute context before being rendered back into the template.
    3. **Template Rendering Process**: Django's template engine, when used by `django-unicorn`, might not automatically apply attribute-specific escaping when variable substitution occurs within HTML attributes. This is because attribute context escaping requires different rules than HTML tag content escaping.  The current implementation relies on general HTML escaping which is insufficient to prevent XSS in HTML attributes.

- Security Test Case:
    1. Create a Django Unicorn component named `AttributeXSS`.
    2. Define a string property `attribute_value` in the component's Python view.
    ```python
    from django_unicorn.components import UnicornView

    class AttributeXSSView(UnicornView):
        attribute_value: str = ""
    ```
    3. Create the component's template (`unicorn/attribute-xss.html`) and use `attribute_value` directly within the `title` attribute of a `div` and bind an input to update it:
    ```html
    <div>
        <div title="{{ attribute_value }}">Hover me</div>
        <input type="text" unicorn:model="attribute_value">
    </div>
    ```
    4. Include the `AttributeXSS` component in a Django template that is served by a Django view.
    5. Access the page in a browser as an external attacker would.
    6. In the input field, enter the XSS payload: `"onmouseover=alert('XSS') a="`.
    7. Move the mouse cursor over the "Hover me" div.
    8. Observe that a JavaScript alert box appears. This confirms the XSS vulnerability because the unescaped payload in the `title` attribute executed JavaScript when the mouse hovered over the div.
