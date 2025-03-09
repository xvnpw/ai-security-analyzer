- Vulnerability Name: Unsafe HTML rendering in templates using `safe` filter or `Meta.safe`

- Description:
    - Django-unicorn allows developers to mark component attributes as 'safe' either in the template using the `|safe` filter or in the component view using `Meta.safe`.
    - This feature is intended to allow rendering of raw HTML, but if user-provided data is marked as safe without proper sanitization, it can lead to Cross-Site Scripting (XSS) vulnerabilities.
    - An attacker can inject malicious JavaScript code through user input, and if this input is rendered in the template marked as safe, the JavaScript code will be executed in the victim's browser.

- Impact:
    - Cross-Site Scripting (XSS)
    - An attacker can execute arbitrary JavaScript code in the victim's browser.
    - This can lead to session hijacking, cookie theft, redirection to malicious websites, or defacement of the website.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - By default, Django-unicorn HTML encodes updated field values to prevent XSS attacks.
    - Developers have to explicitly opt-in to allow a field to be returned without being encoded by using `safe` filter or `Meta.safe`.

- Missing Mitigations:
    - No automatic sanitization of user-provided data when using `safe` filter or `Meta.safe`.
    - Lack of clear and prominent documentation warning developers about the risks of using `safe` filter or `Meta.safe` with user-provided data without sanitization. While documentation mentions security, it could be more explicit about the risks and mitigation strategies.

- Preconditions:
    - The developer must use `safe` filter or `Meta.safe` to render user-provided data in a template.
    - An attacker must be able to inject malicious JavaScript code into the user-provided data.

- Source Code Analysis:
    - File: `django_unicorn/views/views.py`
        - In `_process_component_request` function, the code iterates through `safe_fields` and marks them as safe using `mark_safe`:
        ```python
        # Mark safe attributes as such before rendering
        for field_name in safe_fields:
            value = getattr(component, field_name)
            if isinstance(value, str):
                setattr(component, field_name, mark_safe(value))
        ```
        - `mark_safe` from `django.utils.safestring` marks a string as safe for HTML rendering, bypassing Django's automatic escaping. This is intended for developers to render trusted HTML, but can be dangerous with user input.
        - Visualization:
            ```
            [User Input] --> Component Attribute (marked as safe) --> Template Rendering (raw HTML) --> Browser (XSS if input is malicious)
            ```

    - File: `django-unicorn/docs/source/views.md`
        - Documentation for `safe` meta option explains the default encoding and the opt-in for unencoded fields, but lacks strong warnings about XSS risks when used with user-provided data.

- Security Test Case:
    - Step 1: Create a Django Unicorn component that renders user-provided data using `Meta.safe`.
        - Component View (`safe_xss.py`):
            ```python
            from django_unicorn.components import UnicornView

            class SafeXSSView(UnicornView):
                unsafe_data = ""

                class Meta:
                    safe = ("unsafe_data", )
            ```
        - Component Template (`safe_xss.html`):
            ```html
            <div>
              <input unicorn:model="unsafe_data" type="text" id="unsafe_data_input" />
              <div id="unsafe_data_output">
                {{ unsafe_data }}
              </div>
            </div>
            ```
    - Step 2: Create a Django view and template to include the `safe_xss` component.
        - Django View (`views.py` in Django app):
            ```python
            from django.shortcuts import render
            from django.views.generic import TemplateView

            class SafeXSSComponentView(TemplateView):
                template_name = 'safe_xss_test.html'
            ```
        - Django Template (`safe_xss_test.html`):
            ```html
            {% load unicorn %}
            <html>
            <head>
                {% unicorn_scripts %}
            </head>
            <body>
                {% csrf_token %}
                {% unicorn 'safe-xss' %}
            </body>
            </html>
            ```
    - Step 3: Access the page in a browser and input malicious JavaScript code in the input field, for example: `<img src=x onerror=alert('XSS')>`.
    - Step 4: Observe that the JavaScript code is executed, demonstrating the XSS vulnerability. An alert box with 'XSS' should appear.
    - Step 5: Try the same test case but remove `Meta.safe = ("unsafe_data", )` from the component view.
    - Step 6: Observe that the JavaScript code is not executed, and instead rendered as text, demonstrating the default XSS protection.

- Vulnerability Name: Potential XSS via direct HTML manipulation in Javascript callbacks using `sanitize_html` bypass.

- Description:
    - Django-unicorn uses `sanitize_html` function in `UnicornTemplateResponse._desoupify` to process and clean HTML content before sending it to the frontend.
    - While `sanitize_html` aims to prevent XSS, if Javascript code in frontend directly manipulates the DOM based on component updates without re-sanitization, it can re-introduce XSS vulnerabilities.
    - Specifically, if component updates include seemingly safe HTML that is then manipulated by custom Javascript event listeners or functions, the sanitization applied server-side might be bypassed client-side.
    - An attacker could craft a payload that is considered safe by `sanitize_html` but becomes malicious after client-side manipulation.

- Impact:
    - Cross-Site Scripting (XSS)
    - An attacker can execute arbitrary JavaScript code in the victim's browser by bypassing server-side sanitization through client-side DOM manipulation.
    - This can lead to session hijacking, cookie theft, redirection to malicious websites, or defacement of the website.

- Vulnerability Rank: Medium

- Currently Implemented Mitigations:
    - Server-side HTML sanitization using `django_unicorn.utils.sanitize_html` in `UnicornTemplateResponse._desoupify`.

- Missing Mitigations:
    - Client-side sanitization of any dynamically manipulated HTML content, especially if the manipulation is based on data from component updates.
    - Guidance in documentation discouraging direct DOM manipulation on the client-side based on component updates, and recommending secure practices for dynamic content handling.

- Preconditions:
    - The developer must implement custom Javascript code that directly manipulates the DOM in response to Django-unicorn component updates.
    - The component update must include HTML content that is considered safe by server-side sanitization but can be turned malicious through client-side manipulation.
    - The attacker needs to control part of the component data that influences the client-side DOM manipulation.

- Source Code Analysis:
    - File: `django_unicorn/components/unicorn_template_response.py`
        - `UnicornTemplateResponse.render` method uses `UnicornTemplateResponse._desoupify(soup)` before sending the rendered HTML to the client.
        - `_desoupify` method calls `sanitize_html(init)` when `init_js` is True, and also processes the entire soup object using `soup.encode(formatter=UnsortedAttributes()).decode("utf-8")` which includes sanitization via `formatter=UnsortedAttributes()`.
        - `sanitize_html` function itself is present in `django_unicorn/utils.py`, suggesting an attempt to sanitize JSON data, but not explicitly the HTML DOM after client-side updates.
        - The client-side Javascript might be directly inserting HTML into the DOM without further sanitization, relying solely on server-side sanitization which might be insufficient if the client-side code re-interprets or manipulates the HTML.
        - Visualization:
            ```
            [Server] --> Rendered HTML (sanitized by sanitize_html) --> [Client Browser] --> Javascript Event Listener (DOM manipulation based on component update data) --> Potentially Malicious DOM (if client-side manipulation re-introduces XSS)
            ```

    - File: `django-unicorn/django_unicorn/utils.py`
        - `sanitize_html` function appears to be focused on sanitizing JSON data, not necessarily complex HTML structures after client-side manipulation.

- Security Test Case:
    - Step 1: Create a Django Unicorn component that updates a property with HTML content.
        - Component View (`js_xss.py`):
            ```python
            from django_unicorn.components import UnicornView

            class JSXSSView(UnicornView):
                html_content = "<div>Safe Content</div>"
            ```
        - Component Template (`js_xss.html`):
            ```html
            <div>
              <div id="content-area" u-html="html_content"></div>
            </div>
            ```
    - Step 2: Include this component in a Django template and add custom Javascript to manipulate the content when the component is updated.
        - Django Template (`js_xss_test.html`):
            ```html
            {% load unicorn %}
            <html>
            <head>
                {% unicorn_scripts %}
            </head>
            <body>
                {% csrf_token %}
                {% unicorn 'js-xss' %}

                <script type="application/javascript">
                    document.addEventListener('unicorn:updated', function (event) {
                        if (event.detail.name === 'js-xss') {
                            let contentArea = document.getElementById('content-area');
                            let currentHTML = contentArea.innerHTML;
                            contentArea.innerHTML = currentHTML + '<img src=x onerror=alert("JS_XSS")>'; // Vulnerable DOM manipulation
                        }
                    });
                </script>
            </body>
            </html>
            ```
    - Step 3: Access the page in a browser. Initially, you should see "Safe Content".
    - Step 4: Trigger a component update. This can be done by adding a button and an action that doesn't change any data, just forces an update (e.g., a no-op method in the component view).
        - Add to `js_xss.html`:
            ```html
            <button unicorn:click="noop">Update Component</button>
            ```
        - Add to `js_xss.py`:
            ```python
            def noop(self):
                pass
            ```
    - Step 5: Click the "Update Component" button. Observe that after the update, the Javascript code manipulates the DOM by appending `<img src=x onerror=alert("JS_XSS")>` to the content area.
    - Step 6: Verify that the `alert("JS_XSS")` is executed, demonstrating the XSS vulnerability introduced through client-side DOM manipulation, even though the initial `html_content` was considered safe by server-side sanitization.
