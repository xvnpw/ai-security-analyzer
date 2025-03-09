- **Vulnerability Name:** Reflected Cross–Site Scripting (XSS) via Unsanitized Component State Updates
  - **Description:**
    The Unicorn framework gathers a component’s public properties and injects them into the rendered page inside a JSON “unicorn:data” attribute. Although property values are HTML–escaped by default, if a developer explicitly marks a property as “safe” (using the Meta.safe flag or the |safe template filter) or fails to exclude untrusted fields, then malicious user–supplied input may be rendered without sanitization. For example, an attacker can submit an AJAX payload containing an HTML fragment such as `"><script>alert('xss')</script>` to a property that bypasses escaping.
    - Step by step, an attacker would:
      1. Identify a component whose public property is marked safe (or not excluded) despite holding user–supplied data.
      2. Send a crafted AJAX request (taking advantage of the reactive endpoint) with the malicious payload to update that field.
      3. Force the new state onto the component, which when re–rendered embeds the unsanitized payload into the DOM.
  - **Impact:**
    Successful exploitation can run arbitrary JavaScript in users’ browsers. This may lead to session hijacking, stealing credentials, manipulation of client–side data, or further client–side attacks.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    - By default, public component property values are HTML–escaped upon rendering.
    - The framework uses functions (such as `sanitize_html()`) that map and escape values before inserting them into the template.
    - Developer documentation recommends not exposing sensitive or untrusted data without proper exclusion (e.g. via Meta.exclude or by prefixing with an underscore).
  - **Missing Mitigations:**
    - There is no automatic check that warns when properties containing user–controlled data are marked safe.
    - Advanced sanitization (such as filtering dangerous HTML tags or attributes) is not enforced on fields opted into “safe” output.
  - **Preconditions:**
    - A component property contains user–supplied data.
    - The field is marked safe (via Meta.safe or by using the |safe filter), thereby bypassing built–in escaping.
    - An attacker is authenticated (or otherwise able to trigger the AJAX endpoint) and can supply arbitrary payloads.
  - **Source Code Analysis:**
    - The method (for example, in `UnicornTemplateResponse` in `django_unicorn/components/unicorn_template_response.py`) calls `component.get_frontend_context_variables()`, which collects public component attributes via a helper method (e.g. `_attributes()`) that filters out names starting with an underscore or those listed in Meta.exclude.
    - When a field is opted into “safe” output, its value is passed directly into the JSON payload without being run through the HTML–escaping logic.
    - Tests such as those in `tests/views/test_process_component_request.py` demonstrate that when a “safe” field (as in the FakeComponentSafe example) is updated with HTML (e.g. `<b>test1</b>`), the injected markup appears unescaped in the rendered DOM.
  - **Security Test Case:**
    1. Define a test component with a property (e.g., `comment`) that is explicitly marked safe in its Meta class.
       ```python
       class CommentComponent(UnicornView):
           comment = ""
           class Meta:
               safe = ("comment",)
       ```
    2. Load the page containing the component.
    3. Submit an AJAX update (e.g. via the component’s reactive endpoint) with the payload:
       `"><script>alert('xss')</script>`
    4. Inspect the DOM or view the rendered HTML to ensure that the payload is injected unsanitized and that the JavaScript executes.
    5. Confirm that when the property is not marked safe the payload is instead properly escaped.
