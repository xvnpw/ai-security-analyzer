### Vulnerability List:

#### 1. Cross-Site Scripting (XSS) via Misuse of `safe` Meta Option

- Description:
    1. A Django Unicorn component is created with a property that is intended to render HTML content without escaping. This is achieved by adding the property name to the `safe` tuple within the `Meta` class of the component view.
    2. A template is created to render this component, directly outputting the value of the `safe` property into the HTML without any further sanitization.
    3. User-controlled input is directly or indirectly assigned to this `safe` property without proper sanitization. This could occur through URL parameters, form input, database content, or via user interaction using `unicorn:model`.
    4. An attacker crafts a malicious input containing JavaScript code (e.g., `<img src=x onerror=alert('XSS')>`).
    5. When the component is rendered or updated, the malicious JavaScript code within the `safe` property is injected directly into the HTML output without sanitization.
    6. When a user's browser renders this page, the injected JavaScript code executes, leading to Cross-Site Scripting.

- Impact:
    - **High**
    - Successful exploitation of this vulnerability allows an attacker to execute arbitrary JavaScript code in the victim's browser when they view the affected page. This can lead to:
        - Account takeover by stealing session cookies or credentials.
        - Defacement of the website.
        - Redirection to malicious websites.
        - Theft of sensitive user data displayed on the page.
        - Performing actions on behalf of the user without their consent.

- Vulnerability rank:
    - High

- Currently implemented mitigations:
    - By default, Django Unicorn automatically HTML-encodes all component properties to prevent XSS.
    - The documentation explicitly warns against using the `safe` Meta option with user-controlled data and recommends sanitizing data even when using `safe`.
    - Test case `tests/views/test_process_component_request.py::test_safe_html_entities_not_encoded` confirms that HTML entities are not encoded when `safe` meta option is used.

- Missing mitigations:
    - Django Unicorn does not provide automatic sanitization for properties marked as `safe`. It relies on developers to understand the security implications and manually sanitize any data that is rendered as safe HTML, especially if the data source is untrusted or user-controlled.
    - There are no built-in functions or helpers within Django Unicorn to assist developers in sanitizing HTML content before marking it as safe.
    - Lack of prominent warnings or guidance in the documentation about the critical security implications of using `Meta.safe` without proper sanitization.

- Preconditions:
    1. A Django Unicorn component view must have a `Meta` class with a `safe` tuple that includes a property name.
    2. The component's template must render the value of this `safe` property directly into the HTML, without any additional sanitization template filters.
    3. The value of the `safe` property must be influenced by user input or data from an untrusted source that an attacker can control.
    4. A user input element (e.g., `<input unicorn:model="...">`) may be bound to this `safe` property.

- Source code analysis:
    1. **`django_unicorn/views/__init__.py` - `_process_component_request` function:**
        - Retrieves `safe_fields` from the component's `Meta` class.
        - Iterates through `safe_fields` and uses `mark_safe` to mark the corresponding component attributes as safe for HTML rendering.
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
        - The use of `mark_safe` directly injects the string value into the template without HTML escaping, causing XSS when used with user-controlled data.
    2. **`tests/views/test_process_component_request.py`**:
        - `test_safe_html_entities_not_encoded` test case explicitly verifies that when the `safe` option is used, HTML entities are *not* encoded.
        ```python
        def test_safe_html_entities_not_encoded(client):
            # ...
            assert response["data"].get("hello") == "<b>test1</b>"
            assert "<b>test1</b>" in response["dom"] # <--- "<b>test1</b>" is directly in the DOM
        ```
    3. **Visualization**:
        ```mermaid
        graph LR
            A[User Input] --> B(Component Property - safe=True);
            B --> C{Template Rendering};
            C --> D[HTML Output - No Encoding];
            D --> E[User Browser];
            E -- Executes Malicious Script --> F(XSS Vulnerability);
        ```

- Security test case:
    1. Create a Django app and add it to `INSTALLED_APPS`.
    2. Create a component in `components/xss_component.py` with `unsafe_content` marked as `safe`.
        ```python
        from django_unicorn.components import UnicornView

        class XSSView(UnicornView):
            unsafe_content = ""

            class Meta:
                safe = ("unsafe_content",)
        ```
    3. Create a template for the component in `templates/unicorn/xss.html` rendering `unsafe_content`.
        ```html
        <div>
            <input type="text" unicorn:model="unsafe_content">
            <div>{{ unsafe_content }}</div>
        </div>
        ```
    4. Create a Django view to render the component and pass user-controlled data via GET parameter to `unsafe_content`.
        ```python
        from django.shortcuts import render
        from .components.xss_component import XSSView

        def xss_test_view(request):
            unsafe_input = request.GET.get('input', '')
            component = XSSView(unsafe_content=unsafe_input)
            return render(request, 'xss_test/xss_page.html', {'component': component})
        ```
    5. Create a Django template `templates/xss_test/xss_page.html` to include the component.
        ```html
        {% load unicorn %}
        <!DOCTYPE html>
        <html>
        <head>
            <title>XSS Test</title>
            {% unicorn_scripts %}
        </head>
        <body>
            {% csrf_token %}
            <h1>XSS Vulnerability Test</h1>
            {% unicorn component %}
        </body>
        </html>
        ```
    6. Add a URL pattern to `urls.py` to access the view.
    7. Run the Django development server.
    8. Craft a URL with a malicious JavaScript payload in the `input` parameter: `http://127.0.0.1:8000/xss_test/?input=%3Cimg%20src%3Dx%20onerror%3Dalert(%27XSS%27)%3E`
    9. Open this URL in a web browser.
    10. Observe that an alert box with 'XSS' appears, confirming the XSS vulnerability.

- Recommendation:
    - **Clearly and prominently document the security implications of using the `safe` Meta option.** Emphasize that it bypasses default XSS protection and should only be used with extreme caution.
    - **Recommend and ideally provide helper functions or guidelines for developers to sanitize HTML content** before marking it as `safe`. Suggest using established HTML sanitization libraries in Python.
    - **Consider if Django Unicorn could provide built-in sanitization options** even when `safe` is used, perhaps through configuration or optional parameters. At a minimum, strong warnings and documentation are essential.
    - **Implement a warning or error in development mode when `Meta.safe` is used in conjunction with user-controlled input.**
    - **Develop static analysis tools or linters to detect potential misuse of `safe` attribute.**

#### 2. Partial Update Target Mismatch Leading to Potential Information Disclosure

- Description:
    1. An attacker can manipulate the `target` value in a `callMethod` action's `partial` attribute.
    2. This manipulated `target` is sent to the server.
    3. On the server-side, the `_process_component_request` function uses `BeautifulSoup`'s `find_all()` method to locate DOM elements matching the provided `target` (either by `unicorn:key` or `id`).
    4. Due to using `find_all()` and only taking the first element, if an attacker provides a `target` value that matches multiple elements in the rendered component's DOM, the server might select an unintended element.
    5. Consequently, the partial update could replace a different part of the page than the developer intended.
    6. This can lead to replacing a safe part of the page with content from a sensitive part of the page, resulting in potential information disclosure.

- Impact:
    - **High**
    - Information Disclosure. An attacker can potentially cause the server to replace a designated part of the webpage with content from a different, possibly sensitive, area of the page. This can lead to unintended exposure of information to the user.

- Vulnerability Rank:
    - High

- Currently implemented mitigations:
    - None. The code attempts to retrieve the DOM element based on the provided target, but there is no validation to ensure that the targeted element is the one intended for update by the developer.

- Missing mitigations:
    - Implement server-side validation to verify that the `target` value corresponds to the DOM element that the developer intended to be updated via `unicorn:partial`.
    - Enhance the DOM selection logic to be more precise and prevent attackers from manipulating the `target` to select unintended elements. Consider using more specific selectors or validating the context of the selected element.

- Preconditions:
    - The application utilizes partial updates with the `unicorn:partial` attribute in Django Unicorn components.
    - An attacker can intercept and modify the JSON payload sent to the server when a component action is triggered, specifically manipulating the `target` value within the `partial` attribute of a `callMethod` action.

- Source code analysis:
    - **`django_unicorn/views/__init__.py` - `_process_component_request` function:**
        ```python
        if partial_doms:
            soup = BeautifulSoup(rendered_component, features="html.parser")

            for partial in partials:
                partial_found = False
                only_id = False
                only_key = False

                target = partial.get("target")

                if not target:
                    target = partial.get("key")
                    if target:
                        only_key = True

                if not target:
                    target = partial.get("id")
                    if target:
                        only_id = True

                if not target:
                    raise AssertionError("Partial target is required")

                if not only_id:
                    for element in soup.find_all(): # Vulnerability: find_all() can return multiple elements
                        if "unicorn:key" in element.attrs and element.attrs["unicorn:key"] == target:
                            partial_doms.append({"key": target, "dom": str(element)}) # Only the first element is appended
                            partial_found = True
                            break

                if not partial_found and not only_key:
                    for element in soup.find_all(): # Vulnerability: find_all() can return multiple elements
                        if "id" in element.attrs and element.attrs["id"] == target:
                            partial_doms.append({"id": target, "dom": str(element)}) # Only the first element is appended
                            partial_found = True
                            break
        ```
        - The code uses `soup.find_all()` which can return multiple elements, but only the first match is used for partial update, potentially leading to target mismatch if multiple elements match the attacker-controlled `target`.

- Security test case:
    1. Create a Django Unicorn component named `TargetMismatchComponent`.
    2. In the component's template (`target_mismatch.html`), create two `div` elements:
        - The first `div` with sensitive information and `unicorn:key="sensitive-div"`.
        - The second `div` intended for partial update with safe information and `id="safe-div"`.
        - Add a button with `unicorn:click` action for partial update targeting `safe-div`.
    3. In the component's view (`target_mismatch.py`), create an action method that triggers a partial update for the element with `id="safe-div"`.
    4. Render the `TargetMismatchComponent` in a Django template.
    5. Intercept the JSON payload when the button is clicked.
    6. Modify the `partial` attribute, changing `target` from `"safe-div"` to `"sensitive-div"`.
    7. Send the modified JSON payload to the server.
    8. Verify if the content of `div` with `id="safe-div"` is replaced with the content of `div` with `unicorn:key="sensitive-div"`, confirming the vulnerability.

#### 3. Server-Side Template Injection (SSTI) via Component Arguments

- Description:
    1. An attacker can craft a malicious component name or argument in the `{% unicorn %}` template tag.
    2. When the template is rendered, the `UnicornNode.render` method in `django_unicorn/templatetags/unicorn.py` attempts to resolve the component name and arguments using Django's template variable resolution.
    3. If the component name or arguments are not properly sanitized and contain template language syntax, Django's template engine might execute this syntax during rendering.
    4. This could lead to server-side template injection, allowing the attacker to execute arbitrary Python code on the server.

- Impact:
    - **Critical**
    - Full server compromise. An attacker could potentially execute arbitrary code on the server, read sensitive data, modify data, or cause denial of service.

- Vulnerability rank:
    - Critical

- Currently implemented mitigations:
    - None identified.

- Missing mitigations:
    - Input sanitization and validation of the component name and arguments passed to the `{% unicorn %}` tag.
    - Ensure that component names and arguments are treated as data and not executable code by the template engine in `UnicornNode.render`.

- Preconditions:
    - The attacker needs to be able to influence the component name or arguments used in the `{% unicorn %}` template tag. This could occur if the component name or arguments are dynamically generated based on user-controlled input.

- Source code analysis:
    - **`django_unicorn\templatetags\unicorn.py` - `UnicornNode.render` method:**
        ```python
        def render(self, context):
            # ...
            try:
                component_name = self.component_name.resolve(context) # [!] Component name is resolved using template context
            except AttributeError as e:
                raise ComponentNotValidError(f"Component template is not valid: {self.component_name}.") from e
            # ...
            resolved_args = []
            for value in self.args:
                resolved_arg = template.Variable(value).resolve(context) # [!] Arguments are resolved using template context
                resolved_args.append(resolved_arg)

            resolved_kwargs = self.kwargs.copy()
            for key, value in self.unparseable_kwargs.items():
                try:
                    resolved_value = template.Variable(value).resolve(context) # [!] Keyword arguments are resolved using template context
                    resolved_kwargs.update({key: resolved_value})
                except TypeError:
                    resolved_kwargs.update({key: value})
                except template.VariableDoesNotExist:
                    # ...
        ```
        - Component name, arguments, and keyword arguments are resolved using `template.Variable(value).resolve(context)`, which can lead to SSTI if user input is used without sanitization.

- Security test case:
    1. Create a Django template with dynamic component name from GET parameter.
        ```html
        {% load unicorn %}
        {% csrf_token %}
        {% unicorn component_name %}
        ```
    2. In Django view, pass `component_name` from GET parameter to template context.
        ```python
        from django.shortcuts import render

        def vulnerable_view(request):
            component_name = request.GET.get('component', 'hello-world')
            return render(request, 'vulnerable_template.html', {'component_name': component_name})
        ```
    3. Access vulnerable view with malicious component name: `/?component=injection_test'}}{%20import%20os%20%}{%20print(os.system('whoami'))%20%}{{'injection_test`.
    4. Observe if command `whoami` is executed on the server, confirming SSTI.

#### 4. Cross-Site Scripting (XSS) Vulnerability in Component Data Rendering

- Description:
    1. When a component is rendered, its public attributes are serialized into JSON and embedded in the HTML as a `script` tag.
    2. The JavaScript code in `unicorn.js` parses this JSON data to initialize the component state on the client-side.
    3. If the component data is not properly sanitized before being serialized into JSON, an attacker could inject malicious JavaScript code into the component's attributes.
    4. When the HTML is rendered and the JavaScript parses the JSON data, the malicious JavaScript code will be executed, leading to XSS.

- Impact:
    - **High**
    - Cross-site scripting vulnerability. An attacker could execute arbitrary JavaScript code in the user's browser.

- Vulnerability rank:
    - High

- Currently implemented mitigations:
    - `sanitize_html` function is used in `django_unicorn/components/unicorn_template_response.py` to sanitize the JSON data.
    - Security fix for CVE-2021-42053 in v0.36.0 aimed to prevent XSS.

- Missing mitigations:
    - **Strengthen `sanitize_html`**: Current `sanitize_html` using `html.escape` in `django_unicorn\utils.py` might be insufficient. Consider using a more robust HTML sanitization library.
    - Thorough and consistent sanitization of all component data before JSON serialization.

- Preconditions:
    - The attacker needs to be able to control or influence the data that is set as public attributes in a Unicorn component view, e.g., via user input without sanitization.

- Source code analysis:
    - **`django_unicorn\components\unicorn_template_response.py` - `UnicornTemplateResponse.render` method:**
        ```python
        class UnicornTemplateResponse(TemplateResponse):
            # ...
            def render(self):
                # ...
                init = {
                    "id": self.component.component_id,
                    "name": self.component.component_name,
                    "key": self.component.component_key,
                    "data": orjson.loads(frontend_context_variables), # [!] Component data is loaded
                    "calls": self.component.calls,
                    "hash": content_hash,
                }
                init = orjson.dumps(init).decode("utf-8")
                json_tag = soup.new_tag("script")
                json_tag["type"] = "application/json"
                json_tag["id"] = json_element_id
                json_tag.string = sanitize_html(init) # [!] sanitize_html is called here
                # ...
        ```
        - `sanitize_html(init)` is called before embedding JSON data.

    - **`django_unicorn\utils.py` - `sanitize_html` function:**
        ```python
        def sanitize_html(value: str) -> str:
            """
            Sanitizes HTML to prevent XSS attacks.
            """
            return html.escape(value)
        ```
        - `sanitize_html` uses `html.escape`, which may be insufficient for comprehensive XSS prevention.

- Security test case:
    1. Create a Unicorn component with a public attribute set via URL parameter.
        ```python
        class XSSView(UnicornView):
            vulnerable_data = ""

            def mount(self):
                self.vulnerable_data = self.component_kwargs.get('data', '')
        ```
        ```html
        <div>
            <span id="xss-data">{{ vulnerable_data }}</span>
        </div>
        ```
    2. In Django view, pass `data` from GET parameter as component kwarg.
        ```python
        def xss_view(request):
            data = request.GET.get('data', '')
            return render(request, 'xss.html', {'component': XSSView.as_view(data=data)})
        ```
    3. Access view with malicious payload: `/xss/?data=%3Cscript%3Ealert(%27XSS%27)%3C/script%3E`.
    4. Inspect page source for `<script>` tag in JSON data.
    5. Observe if `alert('XSS')` executes, confirming XSS.

#### 5. Potential HTML Injection via Template Rendering

- Description:
    1. Unicorn uses BeautifulSoup to parse and manipulate HTML during component rendering and updates.
    2. If the component template or data used to render the template contains unescaped HTML entities or tags, and if BeautifulSoup is not configured or used correctly, it could lead to HTML injection vulnerabilities.
    3. This could allow an attacker to inject arbitrary HTML content into the page, potentially leading to defacement, phishing attacks, or other client-side vulnerabilities.

- Impact:
    - **Medium to High**
    - HTML injection vulnerability. Can be used for defacement, phishing, and social engineering attacks; potentially escalated to XSS.

- Vulnerability rank:
    - High

- Currently implemented mitigations:
    - `html.escape` in `sanitize_html` provides some HTML entity escaping, but primarily for JSON XSS prevention, not general HTML injection in templates.

- Missing mitigations:
    - **Enforce HTML escaping in templates**: Ensure all data rendered in templates is HTML-escaped by default using Django's auto-escaping.
    - **Template audit**: Review templates for proper use of Django's auto-escaping or explicit escaping filters.
    - Review BeautifulSoup configuration for HTML injection prevention.

- Preconditions:
    - The component template renders potentially user-controlled or untrusted data without proper HTML escaping.

- Source code analysis:
    - **`django_unicorn\components\unicorn_template_response.py` - `UnicornTemplateResponse.render` method:**
        ```python
        class UnicornTemplateResponse(TemplateResponse):
            # ...
            @timed
            def render(self):
                # ...
                response = super().render() # [!] Django template is rendered here
                content = response.content.decode("utf-8")
                soup = BeautifulSoup(content, features="html.parser") # [!] BeautifulSoup parses the rendered HTML
                # ...
        ```
        - Django template rendering via `super().render()` can introduce HTML injection if templates are not properly escaped.

- Security test case:
    1. Create a Unicorn component rendering a public attribute without escaping.
        ```python
        class HTMLInjectionView(UnicornView):
            injected_html = ""
        ```
        ```html
        <div>
            {{ injected_html }}  <!-- [!] Directly rendering without escaping -->
        </div>
        ```
    2. In Django view, pass malicious HTML payload to `injected_html`.
        ```python
        def html_injection_view(request):
            payload = request.GET.get('payload', '<img src=x onerror=alert("HTMLInjection")>')
            component = HTMLInjectionView()
            component.injected_html = payload # [!] User controlled HTML is set
            return render(request, 'html_injection.html', {'component': component})
        ```
    3. Access view with malicious HTML payload: `/html_injection/?payload=%3Cimg%20src=x%20onerror=alert(%22HTMLInjection%22)%3E`.
    4. Observe if `alert('HTMLInjection')` executes, or if `<img>` tag renders, confirming HTML injection.

#### 6. Cross-Site Scripting (XSS) via Unsafe HTML Attributes Injection

- Description:
    1. An attacker can manipulate component properties to inject malicious HTML attributes into the rendered HTML.
    2. When a component re-renders, injected HTML attributes are included in the server response.
    3. JavaScript code uses `morphdom` to update the DOM.
    4. If injected attributes are interpreted as new attributes by `morphdom` (not text content), they are directly injected into the DOM.
    5. Malicious attributes with JavaScript code (e.g., `onload`, `onerror`) will execute in the user's browser, leading to XSS.

- Impact:
    - **Critical**
    - Successful exploitation leads to arbitrary JavaScript execution, potentially causing session hijacking, account takeover, defacement, etc.

- Vulnerability rank:
    - Critical

- Currently implemented mitigations:
    - HTML encoding for updated field values is mentioned, but insufficient for attribute injection.
    - `safe` Meta option allows disabling HTML encoding, increasing risk if misused.

- Missing mitigations:
    - Insufficient HTML encoding to prevent attribute injection.
    - No explicit input sanitization or attribute encoding for malicious HTML attributes.

- Preconditions:
    - Django Unicorn components with string properties rendered into HTML attributes.
    - Component property reflected into HTML attributes without sanitization in template.

- Source code analysis:
    - **`django_unicorn\components\unicorn_template_response.py` - `UnicornTemplateResponse.render` method:**
        - Sets attributes like `unicorn:id`, `unicorn:name`, `unicorn:data`, and `unicorn:calls` directly on the root element, without attribute sanitization.
        ```python
        root_element["unicorn:id"] = self.component.component_id
        root_element["unicorn:name"] = self.component.component_name
        root_element["unicorn:key"] = self.component.component_key
        root_element["unicorn:checksum"] = checksum
        root_element["unicorn:data"] = frontend_context_variables # Data as attribute
        root_element["unicorn:calls"] = orjson.dumps(self.component.calls).decode("utf-8") # Calls as attribute
        ```
    - **`django_unicorn\views\action_parsers\utils.py` - `set_property_value`:**
        - Sets component properties without sanitization.
        ```python
        setattr(component_or_field, property_name_part, property_value)
        ```
    - **`morphdom`**: Directly injects attributes without browser-side sanitization.

- Security test case:
    1. Create component `XssAttributeView` with property `attribute_value`.
        ```python
        class XssAttributeView(UnicornView):
            attribute_value = ""
        ```
    2. Template `templates\unicorn\xss-attribute.html` renders `attribute_value` as HTML attribute.
        ```html
        <div id="test-div" {{ attribute_value }}></div> <--- Vulnerable attribute injection
        ```
    3. Django view and template to include `xss_attribute` component.
    4. Access page and enter payload `onload="alert('XSS')"` in input field bound to `attribute_value`.
    5. Observe if alert box with "XSS" appears, confirming XSS.

- Vulnerability Status: Valid and not mitigated.

#### 7. Cross-Site Scripting (XSS) via Unsafe HTML Attributes in Component Templates

- Description:
    1. A threat actor can inject malicious JavaScript code into HTML attributes within a Django Unicorn component template.
    2. When the component is rendered or updated, the injected JavaScript code is executed in the user's browser.
    3. This can occur if user-controlled data is included in HTML attributes without proper sanitization within the component's template.

- Impact:
    - **High**
    - Successful exploitation allows arbitrary JavaScript execution, leading to session hijacking, defacement, data theft, etc.

- Vulnerability rank:
    - High

- Currently implemented mitigations:
    - Default HTML encoding of field values, but insufficient for attributes.
    - `safe` Meta attribute requires developers to consciously mark fields as safe.

- Missing mitigations:
    - No automatic sanitization for HTML attributes within templates.
    - Developers need to manually sanitize user-provided data before rendering in attributes.
    - No clear guidance in documentation about risks of user input in HTML attributes.

- Preconditions:
    - Django Unicorn components rendering user-controlled data in HTML attributes within templates.
    - Developers fail to manually sanitize user-provided data in attributes.

- Source code analysis:
    - `django_unicorn\views\action_parsers\utils.py` - `set_property_value`: HTML encoding for field *values*, not attributes.
    - `django_unicorn\templatetags\unicorn.py` - `unicorn` template tag: No explicit HTML sanitization for attributes.
    - Fix for CVE-2021-42053: Focuses on encoding field values, not attributes.

- Security test case:
    1. Component template `unicorn/attribute-xss.html`:
        ```html
        <div id="test-attr" data-user="{{ user_input }}">Hello</div>
        ```
    2. Component view `AttributeXSSView` with `user_input` property.
        ```python
        class AttributeXSSView(UnicornView):
            user_input: str = ""

            def mount(self):
                if 'malicious_input' in self.request.GET:
                    self.user_input = self.request.GET['malicious_input']
                else:
                    self.user_input = "initial value"
        ```
    3. Django template to render component.
    4. Access page with malicious payload in URL: `/?malicious_input=%22%3E%3Cimg%20src=x%20onerror=alert(document.domain)%3E`.
    5. Observe if JavaScript executes (alert box), confirming XSS.
