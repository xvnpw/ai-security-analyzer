### 1. Cross-Site Scripting (XSS) vulnerability due to unsafe string coercion in kwargs

* Description:
    1. An attacker can craft a malicious URL that passes a string as a kwarg to a Unicorn component through template rendering context (e.g., `request.GET`).
    2. If the component's template directly renders this kwarg, for example using `{{ my_kwarg }}`, without explicit HTML sanitization, the string value is rendered as is.
    3. If the attacker provides JavaScript code within this string (e.g., `<script>alert("XSS")</script>`), it will be executed in the user's browser, leading to XSS.
    4. This is because Django templates, while auto-escaping by default, will render context variables directly unless they are explicitly marked as safe or further sanitized. If kwargs from URL parameters are directly passed into the template context via the `unicorn` template tag and rendered, they are susceptible to this vulnerability.

* Impact:
    * An attacker can execute arbitrary JavaScript code in the victim's browser.
    * This can lead to session hijacking, cookie theft, defacement of the website, or redirection to malicious sites.

* Vulnerability rank: High

* Currently implemented mitigations:
    * The documentation (`docs\source\changelog.md`) mentions HTML encoding in responses as a fix for CVE-2021-42053 in version 0.36.0. This likely refers to Django's default auto-escaping of template variables, which is generally active.
    * The file `django_unicorn\utils.py` includes `sanitize_html` function. However, source code analysis of `django_unicorn\components\unicorn_template_response.py` shows that this function is used specifically for escaping HTML characters for JSON output within `<script>` tags (`UnicornTemplateResponse._desoupify` and `UnicornTemplateResponse.render` for `init_script` and `json_tag`). It is not applied generally to all template variable rendering, particularly not to kwargs passed to the `unicorn` template tag.

* Missing mitigations:
    * Input sanitization for kwargs passed to components via the `unicorn` template tag is not automatically implemented. The framework relies on Django's default template auto-escaping, which might be insufficient if developers explicitly mark content as safe or bypass auto-escaping.
    * Consistent HTML encoding should be enforced for all rendered content originating from user-controlled sources, including kwargs passed via the `unicorn` template tag, especially when rendered in component templates.
    * Developers should be strongly warned against directly rendering kwargs in templates without explicit sanitization, particularly when expecting non-string types or when kwargs originate from URL parameters or other potentially attacker-controlled inputs.
    * There is no clear mechanism within django-unicorn to automatically sanitize kwargs before they are passed to the template context or rendered by the `unicorn` template tag.

* Preconditions:
    * The application must be using django-unicorn.
    * A component must be designed to accept kwargs via the `unicorn` template tag and render them directly in its template.
    * The kwargs rendered in the template must originate from a user-controllable source, such as URL parameters or form inputs, and be passed to the component via the `unicorn` template tag.

* Source code analysis:
    1. **File: `django_unicorn\templatetags\unicorn.py`**:
        - The `unicorn` template tag (`register.tag("unicorn", unicorn)`) is defined in this file and is responsible for rendering components within Django templates.
        - The `unicorn` function and `UnicornNode` class handle parsing tag arguments and kwargs provided in the template.
        - Crucially, kwargs are extracted from the template tag arguments and resolved directly using Django's template variable resolution: `template.Variable(value).resolve(context)`. This resolution process allows kwargs to directly incorporate values from the template context, including potentially unsafe `request.GET` parameters, if passed in the template.
        - There is no explicit HTML sanitization or encoding of kwargs happening within `django_unicorn\templatetags\unicorn.py` before they are passed to the component or rendered in the template. This means any user-provided data passed as kwargs is taken as is and given to the template context.
    2. **File: `django_unicorn\components\unicorn_template_response.py`**:
        - This file handles the actual rendering of the component's template using Django's template engine.
        - It employs `BeautifulSoup` to parse the rendered HTML output for the purpose of adding component-specific attributes (like `unicorn:id`, `unicorn:data`) which are used by the frontend JavaScript to manage component behavior.
        - The `sanitize_html` function from `django_unicorn\utils.py` is imported and used within `UnicornTemplateResponse._desoupify` and `UnicornTemplateResponse.render`. However, its application is limited to sanitizing the JSON data that is embedded within `<script type="application/json">` tags for component initialization. This is a specific measure for internal data serialization to prevent issues within JSON in HTML, and not a general-purpose template output escaping mechanism for component variables or kwargs.
        - The primary template rendering is performed by Django's template engine. By default, Django's template engine does apply auto-escaping to variables to prevent basic XSS. However, this auto-escaping can be explicitly bypassed by developers using the `safe` filter in templates or by marking context variables as 'safe' at the view level. If kwargs, especially those derived from user inputs like URL parameters, are rendered in templates without additional sanitization and if auto-escaping is bypassed, or if the kwargs are somehow pre-marked as safe, then XSS vulnerabilities can occur.
    3. **File: `django_unicorn\utils.py`**:
        - The `sanitize_html` function in this utility module offers HTML escaping capabilities. However, it's important to note that django-unicorn does not automatically apply this function to kwargs or template variables in a general sense. As analyzed in `django_unicorn\components\unicorn_template_response.py`, its usage is confined to sanitizing JSON data embedded in `<script>` tags. It's not designed or implemented to be a global output escaping function for all template contexts or variables, including kwargs.
    4. **File: General observation**:
        - Django's built-in template auto-escaping remains the primary XSS mitigation mechanism within django-unicorn. The library itself does not introduce any extra layers of automatic sanitization specifically tailored for kwargs or component properties that are rendered in templates, beyond Django's default settings.
        - The identified XSS risk is realized when developers directly render kwargs within component templates, particularly if these kwargs originate from user-controlled inputs (like URL parameters), and are not explicitly sanitized using Django's `escape` filter or a similar method. Furthermore, if developers intentionally or inadvertently bypass Django's auto-escaping, the risk is amplified.

* Security test case:
    1. Create a Django project with django-unicorn installed and configured as described in `README.md`.
    2. Create a component named `xss_kwarg_test` in `myapp/components/xss_kwarg_test.py` with the following content:
    ```python
    from django_unicorn.components import UnicornView

    class XssKwargTestView(UnicornView):
        value = ""

        def mount(self, initial_value="default"):
            self.value = initial_value
    ```
    3. Create a template for the component in `myapp/templates/unicorn/xss_kwarg_test.html` with the following content:
    ```html
    <div>
        <p>Rendered Kwarg Value: {{ value }}</p>
    </div>
    ```
    4. Create a Django view in `myapp/views.py` to render a template that includes the `xss_kwarg_test` component and passes a kwarg named `initial_value` which is directly derived from `request.GET`:
    ```python
    from django.shortcuts import render

    def home(request):
        return render(request, 'home.html')
    ```
    5. Create a template `myapp/templates/home.html` with the following content:
    ```html
    {% load unicorn %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        {% unicorn 'xss-kwarg-test' initial_value=request.GET.xss %}
    </body>
    </html>
    ```
    6. Configure `urls.py` to include unicorn URLs and the new `home` view.
    7. Run the Django development server.
    8. Access the URL `/` with a malicious payload in the `xss` query parameter, for example: `/?xss=<script>alert("XSS")</script>`.
    9. Observe if the JavaScript code in the `xss` parameter is executed in the browser. If an alert box appears, it confirms the XSS vulnerability due to unsafe kwarg rendering.
