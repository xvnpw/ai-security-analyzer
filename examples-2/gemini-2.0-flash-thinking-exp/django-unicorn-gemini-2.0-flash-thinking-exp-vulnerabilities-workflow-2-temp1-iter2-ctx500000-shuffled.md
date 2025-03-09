## Combined Vulnerability List

The following vulnerabilities have been identified in the Django Unicorn project. These are considered high or critical severity and represent realistic threats that could be exploited by attackers.

### Vulnerability: Cross-Site Scripting (XSS) via `Meta.safe` attribute

- **Description:**
    1. A developer, intending to optimize performance or handle pre-sanitized HTML, uses the `Meta.safe` attribute within a Django Unicorn component to explicitly mark a component property as safe from HTML encoding.
    2. Unknowingly or mistakenly, user-controlled input is directly bound to this property using `unicorn:model` in the component's template. This means data typed by a user in an input field is directly assigned to the `safe` property.
    3. A malicious attacker crafts an input containing malicious JavaScript code, such as `<img src=x onerror=alert('XSS Vulnerability')>`, and injects it into the input field bound to the `safe` property.
    4. When the Django Unicorn component re-renders (e.g., on user input or other component updates), the value of the `safe` property, now containing the malicious JavaScript, is included in the rendered HTML. Crucially, because the property is marked as `safe`, Django Unicorn bypasses the standard HTML encoding for this specific property.
    5. The user's browser receives the re-rendered HTML containing the unsanitized JavaScript. As the JavaScript is not encoded, the browser interprets it as executable code and immediately executes it. This results in a Cross-Site Scripting (XSS) vulnerability.

- **Impact:**
    - **High**. Exploiting this vulnerability allows an attacker to execute arbitrary JavaScript code within the context of a victim's browser session when they interact with the vulnerable Django Unicorn component.
    - This can have severe consequences, including:
        - **Session Hijacking:** Attackers can steal session cookies, allowing them to impersonate the victim user and gain unauthorized access to their account and data.
        - **Cookie Theft:** Sensitive information stored in cookies can be exfiltrated and used for malicious purposes.
        - **Redirection to Malicious Websites:** Users can be silently redirected to attacker-controlled websites, potentially leading to further phishing attacks or malware infections.
        - **Website Defacement:** The visual appearance of the web page can be altered, damaging the website's reputation and potentially misleading users.
        - **Performing Actions on Behalf of the User:** Attackers can make requests to the server as the victim user, potentially modifying data, performing unauthorized transactions, or gaining further access to sensitive resources, depending on the application's functionality.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - **Default HTML Encoding:** Django Unicorn, by default, automatically HTML-encodes updated field values that are passed from the backend to the frontend. This serves as a general, broad mitigation against many common XSS attack vectors, but it is explicitly bypassed by the `Meta.safe` attribute.
    - **Documentation Warnings:** Django Unicorn documentation includes warnings against placing sensitive data into publicly accessible component properties. This is a general security best practice, but doesn't specifically address the risks associated with `Meta.safe`.
    - **`Meta.safe` and `safe` Filter Documentation:** Documentation explains the intended purpose and correct usage of `Meta.safe` and the `safe` template filter. While this indirectly warns against misuse by emphasizing developer responsibility when using these features, it lacks a direct and explicit warning about the XSS risks of using `Meta.safe` with user-controlled input.

- **Missing Mitigations:**
    - **Explicit Code Warnings/Checks:** There are no specific warnings or runtime checks within the Django Unicorn code to detect or prevent developers from using `Meta.safe` in conjunction with user-controlled input that hasn't been properly sanitized. The framework currently trusts the developer to use `Meta.safe` correctly and safely.
    - **Built-in Sanitization:** Django Unicorn does not enforce or provide any built-in sanitization functions that developers are required or encouraged to use when they choose to utilize `Meta.safe`. Developers are left to implement their own sanitization, increasing the risk of mistakes and vulnerabilities if they are not security-conscious or lack sufficient expertise in secure coding practices.

- **Preconditions:**
    - **`Meta.safe` Usage:** A Django Unicorn component must be configured to use the `Meta.safe` attribute to mark at least one property as safe from HTML encoding. This indicates an explicit developer decision to bypass default encoding for that specific property.
    - **`unicorn:model` Binding:** User input from a form field (typically an `<input>`, `<textarea>`, or `<select>` element) must be bound to the `safe` property using the `unicorn:model` directive. This establishes the data flow from user input to the vulnerable component property.
    - **Lack of Sanitization:** Critically, the developer using `Meta.safe` must fail to implement proper sanitization of the user input *before* marking it as safe. This is the core vulnerability – the assumption that data marked `safe` is indeed safe, without verifying its source or content.

- **Source Code Analysis:**
    1. The rendering process in Django Unicorn starts in `django_unicorn/components/unicorn_template_response.py` within the `UnicornTemplateResponse.render` method. This method is responsible for orchestrating the rendering of the component and preparing the data to be sent to the frontend.
    2. Inside `UnicornTemplateResponse.render`, the crucial step `root_element["unicorn:data"] = frontend_context_variables` serializes the component's data into a JSON string (`frontend_context_variables`). This JSON data is then embedded within the HTML as a `unicorn:data` attribute on the root component element.
    3. The `frontend_context_variables` are constructed by the `UnicornView.get_frontend_context_variables` method in `django_unicorn/components/unicorn_view.py`. This method is where the `Meta.safe` attribute is processed.
    4. Within `UnicornView.get_frontend_context_variables`, the code retrieves the list of fields declared as `safe` from the component's `Meta` class: `safe_fields = getattr(meta, "safe", ())`.
    5. The code then iterates through each field name listed in `safe_fields`. For each `field_name`, it retrieves the corresponding property value from the component instance using `getattr(self, field_name)`.
    6. The critical line of code that introduces the vulnerability is:

    ```python
    # File: django_unicorn/components/unicorn_view.py
    if isinstance(value, str):
        setattr(self, field_name, mark_safe(value))  # noqa: S308
    ```
    If the value of a property listed in `Meta.safe` is a string, the code uses Django's `mark_safe()` function to explicitly mark it as safe for template rendering. This bypasses Django's automatic HTML escaping for this specific value.
    7. Consequently, if a developer has marked a property that is directly populated with user input (via `unicorn:model`) as `safe` without any prior sanitization, the `mark_safe()` function will ensure that any malicious JavaScript injected by a user within that input is rendered directly into the HTML output, without any encoding. This direct rendering into the HTML then leads to the browser executing the injected JavaScript, resulting in the XSS vulnerability.

    **Visualization:**

    ```
    User Input (Malicious JS) --> unicorn:model --> Component Property (marked as Meta.safe) --> get_frontend_context_variables --> mark_safe() --> UnicornTemplateResponse.render --> HTML Output (Unsanitized JS) --> Browser executes JS (XSS)
    ```

- **Security Test Case:**
    1. Create a new Django app (if you don't already have one) and within it, create a Django Unicorn component named `xss_safe_component` by creating the file `components/xss_safe_component.py`.
    2. Define the component view class `XssSafeView` in `components/xss_safe_component.py`.  This component will have a property named `text` which will be marked as `safe` in the `Meta` class. This simulates a developer mistakenly marking a user-controlled input as safe.

    ```python
    # File: components/xss_safe_component.py
    from django_unicorn.components import UnicornView

    class XssSafeView(UnicornView):
        text = ""

        class Meta:
            safe = ("text", ) # Mark 'text' property as safe
    ```
    3. Create the component's template file `templates/unicorn/xss_safe_component.html`. This template will contain an input field bound to the `text` property using `unicorn:model="text"` and will display the value of the `text` property within a `div` element.

    ```html
    <!-- File: templates/unicorn/xss_safe_component.html -->
    <div>
        <input type="text" unicorn:model="text"> <br>
        <div id="output">Output: {{ text }}</div>
    </div>
    ```
    4. Create a Django template, for example, `xss_safe_test.html`, within your app's `templates` directory. This template will include the Django Unicorn scripts and embed the `xss_safe_component` using the `{% unicorn 'xss-safe' %}` tag.

    ```html
    {% load unicorn %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        <h1>XSS via Meta.safe Vulnerability Test</h1>
        {% unicorn 'xss-safe' %}
    </body>
    </html>
    ```
    5. In your Django app's `views.py`, create a Django view function to render the `xss_safe_test.html` template. Also, configure a URL path in `urls.py` to access this view (e.g., `/xss-safe-test/`).
    6. Access the configured URL (e.g., `http://localhost:8000/xss-safe-test/`) in a web browser. You should see the input field rendered by the `xss_safe_component`.
    7. In the input field, enter the following standard JavaScript XSS payload: `<img src=x onerror=alert('XSS Vulnerability')>`.
    8. After typing the payload, trigger a component update. This can usually be done by clicking outside the input field, pressing tab, or simply waiting a short moment (depending on the debounce settings, if any).
    9. **Observe the result:** If an alert box pops up in the browser window displaying the message "XSS Vulnerability", it confirms the vulnerability. This indicates that the JavaScript code you injected was executed because the `Meta.safe` attribute prevented HTML encoding of the input.
    10. **Inspect the HTML source:** To further verify, inspect the HTML source code of the page (usually by right-clicking and selecting "View Page Source" or similar in your browser's developer tools). Look for the `div` with the ID `output`. You should see that the injected `<img src=x onerror=alert('XSS Vulnerability')>` is present in the HTML *exactly as you typed it*, without any HTML entity encoding. This directly confirms that the `Meta.safe` attribute is bypassing the expected HTML encoding and leading to the XSS vulnerability.


### Vulnerability: Cross-Site Scripting (XSS) in Component Rendering via Template Variables

- **Description:**
    1. A developer creates a Django Unicorn component and, within its template (`.html` file), renders user-controlled data directly into an HTML template variable using Django's template language (e.g., `{{ user_input }}`).
    2. The developer assumes that Django's default template auto-escaping will automatically protect against XSS. However, auto-escaping might not always be sufficient, especially if the data is intended to be rendered in contexts where HTML is expected, or if developers are using template filters like `safe` incorrectly.
    3. An attacker identifies this component and finds a way to inject malicious input. This input could be provided through various means, such as:
        - Form fields bound to component properties using `unicorn:model`.
        - URL parameters that influence component state.
        - Any other mechanism that can control the data rendered by the component's template variable.
    4. The attacker crafts a malicious input string containing JavaScript code. A typical XSS payload might be `<img src=x onerror=alert('XSS-test')>`.
    5. When a user interacts with the application in a way that triggers the rendering of this vulnerable component with the attacker's malicious input, the JavaScript code is injected into the HTML output.
    6. Because the template variable is rendered without explicit sanitization within the component's Python code, and Django's auto-escaping is either bypassed, insufficient for the context, or not in effect (if the `safe` filter was misused), the malicious JavaScript is included in the HTML as executable code.
    7. When the user's browser renders this HTML, the injected JavaScript code executes, resulting in a Cross-Site Scripting (XSS) vulnerability.

- **Impact:**
    - **High**. Similar to the previous vulnerability, this XSS allows an attacker to execute arbitrary JavaScript code in the browser of any user viewing the page containing the vulnerable Django Unicorn component.
    - The potential impacts are the same as described in the "XSS via `Meta.safe` attribute" vulnerability, including session hijacking, cookie theft, redirection, website defacement, and actions performed on behalf of the user.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - **Django's Default Template Auto-escaping:** Django's template engine has automatic HTML escaping enabled by default. This is intended to prevent basic XSS attacks by converting potentially harmful HTML characters (like `<`, `>`, `&`, `'`, `"`) into their HTML entity equivalents. However, auto-escaping is context-dependent and can be bypassed in various situations, especially when developers explicitly tell Django that content is "safe".
    - **Documentation Mentions Security and CSRF:** Django Unicorn documentation mentions general security considerations, such as the necessity of using CSRF tokens to protect against Cross-Site Request Forgery attacks. However, the documentation lacks specific and prominent warnings about the dangers of rendering unsanitized user input in templates and the potential for XSS, beyond the implied risks of using the `safe` filter.
    - **Changelog Mentions XSS Fixes:** The Django Unicorn changelog mentions a security fix for CVE-2021-42053 (in version v0.36.0). This fix was related to preventing XSS attacks and involved HTML encoding responses. This indicates that the project team is aware of XSS risks and has addressed them in the past.

- **Missing Mitigations:**
    - **Lack of Server-Side Sanitization:** Django Unicorn itself does not provide or enforce any server-side sanitization of user inputs before they are rendered in templates. The framework relies on developers to manually sanitize user input before passing it to component templates for rendering. This places the burden of preventing XSS entirely on the developer and increases the likelihood of vulnerabilities due to developer error or oversight.
    - **No Explicit Documentation Guidelines on Sanitization:** While general Django security practices apply, there is a lack of clear and prominent guidelines within the Django Unicorn documentation specifically instructing developers on how to properly sanitize user inputs within Django Unicorn components to prevent XSS. The documentation mentions the `safe` filter, but does not dedicate a section to secure template rendering and XSS prevention best practices.
    - **No Built-in Sanitization Mechanisms:** Django Unicorn does not offer any built-in functions, decorators, or mechanisms that would automatically sanitize data rendered in templates or encourage developers to sanitize data as a standard practice. The reliance on Django's default auto-escaping and the availability of the `safe` filter, without sufficient guidance, can mislead developers into a false sense of security or encourage insecure practices if `safe` is misused.

- **Preconditions:**
    - **User-Controlled Data in Template:** A Django Unicorn component must be designed in a way that it renders user-controlled data directly into a template variable within its `.html` template file. This means that the content displayed to the user is directly derived from user input.
    - **No Manual Sanitization:** The developer must have failed to manually sanitize the user-controlled data *before* passing it to the template variable or rendering it. This lack of sanitization is the direct cause of the vulnerability.
    - **Attacker Input Injection:** An attacker needs to be able to inject malicious input that will be processed by the vulnerable component. This could be through form submissions, URL parameters, or any other method that allows the attacker to manipulate the data that ends up in the template variable.

- **Source Code Analysis:**
    - **`django_unicorn\templatetags\unicorn.py`**: This file contains the Django template tags (`{% unicorn ... %}`) that are used to embed Django Unicorn components into Django templates. The rendering process begins here, but the code focuses on component lifecycle management and rendering, not explicit data sanitization. Django's template engine's auto-escaping would be active when rendering variables within the template, but as noted, this is context-dependent.
    - **`django_unicorn\views\views.py`**: The `render()` function in `UnicornView` and `UnicornTemplateResponse` are responsible for handling the rendering of the component on the server-side and preparing the response. However, these files do not contain any explicit code that sanitizes component data before it is passed to the template for rendering. The focus is on component state management and communication with the frontend.
    - **`django_unicorn\docs\source\templates.md`**: The documentation section on templates explains how to use template tags and attributes within Django Unicorn components. It mentions the `safe` filter and its use cases, implying that developers need to be aware of when *not* to use it for security reasons, but lacks a comprehensive security section on data sanitization and XSS prevention specifically for template variables.
    - **`django_unicorn\docs\source\changelog.md`**: The mention of CVE-2021-42053 and the HTML encoding fix in version v0.36.0 in the changelog confirms that XSS vulnerabilities have been a concern in the past and that the project has previously addressed them through HTML encoding. However, this past fix doesn't guarantee protection against all forms of XSS, especially when developers render unsanitized user input in templates.

- **Security Test Case:**
    1. Create a basic Django Unicorn component to demonstrate the vulnerability. Start by creating the component file `example_app/components/xss_component.py` (assuming you have a Django app named `example_app`).

        ```python
        # example_app/components/xss_component.py
        from django_unicorn.components import UnicornView

        class XssView(UnicornView):
            user_input = ""
        ```

    2. Create the component's template file `example_app/templates/unicorn/xss.html`. This template will display the `user_input` property directly within a `<p>` tag using `{{ user_input }}` and will include an input field bound to the `user_input` property using `unicorn:model="user_input"`.

        ```html
        <!-- example_app/templates/unicorn/xss.html -->
        <div>
            <p>User Input: {{ user_input }}</p>
            <input type="text" unicorn:model="user_input" id="user-input">
        </div>
        ```

    3. Create a Django view function in `example_app/views.py` to render a page that includes this `XssView` component.

        ```python
        # example_app/views.py
        from django.shortcuts import render

        def xss_test_view(request):
            return render(request, 'xss_test_page.html')
        ```

    4. Create the Django template `example_app/templates/xss_test_page.html` to include the Unicorn scripts and embed the `XssView` component using `{% unicorn 'xss' %}` (assuming you name your component 'xss' in your URL configuration).

        ```html
        <!-- example_app/templates/xss_test_page.html -->
        {% load unicorn %}
        <html>
        <head>
            {% unicorn_scripts %}
        </head>
        <body>
            {% csrf_token %}
            {% unicorn 'xss' %}
        </body>
        </html>
        ```

    5. Configure a URL path in your Django app's `urls.py` to map a URL (e.g., `/xss-test/`) to the `xss_test_view` you created.
    6. Access the configured URL (e.g., `http://localhost:8000/xss-test/`) in your web browser. You should see the input field and the "User Input:" paragraph from your `xss.html` component template.
    7. In the input field, enter the following XSS payload: `<img src=x onerror=alert('XSS-test')>`.
    8. After entering the payload, trigger a component update by clicking outside the input field or pressing tab.
    9. **Observe the result:** If an alert box pops up displaying "XSS-test", it confirms that the JavaScript code was executed. This means the template rendering of `{{ user_input }}` is vulnerable to XSS when unsanitized user input is provided.
    10. **Examine the HTML source:** Inspect the HTML source code of the page. Look for the `<p>User Input: ...</p>` element. If you see the injected JavaScript payload `<img src=x onerror=alert('XSS-test')>` present *verbatim* within the `<p>` tags, without HTML entity encoding (e.g., not encoded as `&lt;img src=x ...`), it further validates the XSS vulnerability. This indicates that Django's auto-escaping was either not effective or was bypassed in this context, allowing the malicious JavaScript to be rendered and executed.
