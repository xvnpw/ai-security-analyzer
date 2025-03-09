### Vulnerability: Cross-Site Scripting (XSS) through unsafe HTML attributes in templates

* Description:
    1. An attacker can inject malicious JavaScript code into a Django template used by a Unicorn component through user-controlled input.
    2. When the component is rendered or updated via AJAX, the injected JavaScript is included in the HTML attributes of the rendered component.
    3. When the browser parses and renders the HTML, the malicious JavaScript code embedded within the attributes is executed, leading to Cross-Site Scripting (XSS).
    4. This vulnerability occurs if a developer directly embeds user-controlled input into HTML attributes within a component template and explicitly marks it as 'safe' using the `safe` template filter or `Meta.safe` attribute, bypassing the default HTML encoding.

* Impact:
    * Critical
    * Successful exploitation allows an attacker to execute arbitrary JavaScript code in the victim's browser when they view a page containing the vulnerable Unicorn component.
    * This can lead to severe security consequences, including session hijacking, website defacement, redirection to malicious websites, theft of sensitive user data, and other unauthorized actions.

* Vulnerability Rank: critical

* Currently implemented mitigations:
    * Django-unicorn, by default, HTML-encodes updated field values to prevent XSS attacks. This is a general safeguard applied to component data.
    * Developers are required to explicitly use the `safe` Meta attribute in the component class or the `safe` template filter in templates to disable HTML encoding for specific variables, allowing for raw HTML rendering when intentionally needed.

* Missing mitigations:
    * The current mitigation relies on developers understanding the security implications of using `safe` and consistently applying secure coding practices. There is no automated mechanism to detect or warn developers against the insecure use of `safe` with user-controlled data, especially within HTML attributes.
    * The framework lacks a mechanism to enforce Content Security Policy (CSP) by default. CSP could provide an additional layer of defense against XSS attacks, even if the default encoding is bypassed or `safe` is misused.

* Preconditions:
    * A developer must intentionally use the `safe` Meta attribute or the `safe` template filter within a Unicorn component template. This action is required to bypass the default HTML encoding.
    * User-controlled data must be dynamically rendered into an HTML attribute within the component's template and incorrectly marked as safe. This scenario arises when developers assume the input is safe or fail to recognize the attribute context's vulnerability to XSS.

* Source code analysis:
    1. **File: ..\django-unicorn\docs\source\views.md** (from previous analysis)
        - Highlights the `Meta.safe` attribute, explaining that it is used to "explicitly opt-in to allow a field to be returned without being encoded". This documentation, while explaining the feature, does not sufficiently warn against the risks of using `safe` with user-provided input in attribute contexts.
    2. **File: ..\django-unicorn\docs\source\templates.md** (from previous analysis)
        - Mentions "Unicorn attributes usually start with `unicorn:`", indicating that standard HTML attributes are also permissible in Unicorn templates. This is relevant as the vulnerability is in standard HTML attributes, not Unicorn-specific ones.
    3. **File: ..\django-unicorn\components\unicorn_template_response.py** (from previous analysis)
        - The `UnicornTemplateResponse.render` function is responsible for rendering the component template and applies sanitization based on the `safe` meta attribute.
        - The `sanitize_html` function within this module is used for sanitization, but its effectiveness in the context of HTML attributes when `safe` is explicitly used needs careful review. The current implementation might primarily focus on sanitizing element content, potentially overlooking the nuanced requirements for attribute contexts, especially when developers bypass default protections using `safe`.

    **Vulnerability analysis:**
    The vulnerability arises when a developer uses `safe` to render user input directly into an HTML attribute, such as `<div title="{{ unsafe_input|safe }}">`. If `unsafe_input` contains a malicious payload like `"><img src=x onerror=alert(1)>`, the rendered HTML becomes `<div title=""><img src=x onerror=alert(1)>">`. Browsers will interpret the content within the `title` attribute, and the `onerror` event handler in the injected `<img>` tag will execute the JavaScript `alert('XSS')`. This demonstrates a bypass of standard HTML encoding and leads to XSS because the sanitization might not be robust enough for attribute contexts when `safe` is explicitly enabled. The risk is compounded by the lack of clear guidance against this practice in the documentation and the absence of automated checks to prevent such insecure usage.

* Security test case:
    1. Set up a new Django project and integrate `django_unicorn` into `INSTALLED_APPS`.
    2. Create a Unicorn component named `attribute_xss` in `components/attribute_xss.py`:
    ```python
    from django_unicorn.components import UnicornView

    class AttributeXssView(UnicornView):
        unsafe_input = ""

        class Meta:
            safe = ("unsafe_input",)
    ```
    3. Define the component's template at `templates/unicorn/attribute-xss.html`:
    ```html
    <div>
        <input unicorn:model="unsafe_input" type="text" />
        <div title="{{ unsafe_input|safe }}">Hover me</div>
    </div>
    ```
    4. Create a Django view to render a template that includes the `attribute_xss` component in `views.py`:
    ```python
    from django.shortcuts import render

    def attribute_xss_view(request):
        return render(request, 'attribute_xss_test.html')
    ```
    5. Create a Django template `templates/attribute_xss_test.html` to embed the component:
    ```html
    {% load unicorn %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        {% unicorn 'attribute-xss' %}
    </body>
    </html>
    ```
    6. Configure `urls.py` to include the view and unicorn URLs.
    7. Launch the Django development server.
    8. Access the `attribute_xss_test` view in a web browser.
    9. In the input field, enter the XSS payload: `"><img src=x onerror=alert('XSS')>`
    10. Hover the mouse over the "Hover me" div.
    11. Observe an alert box displaying 'XSS', confirming successful XSS exploitation through HTML attributes.

### Vulnerability: Potential Cross-Site Scripting (XSS) through morphdom's RELOAD_SCRIPT_ELEMENTS

* Description:
    1. The `RELOAD_SCRIPT_ELEMENTS` setting, when enabled in morphdom configuration, causes script elements within Unicorn components to be reloaded and re-executed during component updates. This is not the default setting.
    2. If a component template includes an inline `<script>` tag that contains user-controlled content (e.g., derived from a component property marked as `safe`), and `RELOAD_SCRIPT_ELEMENTS` is set to `True`, morphdom will reload and re-execute this script tag upon any component update.
    3. Should the user-controlled content within the `<script>` tag contain malicious JavaScript, this code will be re-executed every time the component updates, potentially leading to persistent or repeated XSS.
    4. This vulnerability path is contingent on both enabling a non-default setting (`RELOAD_SCRIPT_ELEMENTS`) and a developer's insecure practice of embedding user input within `<script>` tags while using `safe`.

* Impact:
    * High
    * If exploited, an attacker can inject and re-execute JavaScript code. This is contingent on `RELOAD_SCRIPT_ELEMENTS` being enabled and developers making insecure use of `<script>` tags with user input in component templates, marking the input as `safe`.
    * The impact can range from account compromise to data theft and other malicious activities. While slightly less direct than typical XSS vulnerabilities due to its reliance on a non-default setting, it still represents a significant risk in environments where `RELOAD_SCRIPT_ELEMENTS` is enabled.

* Vulnerability Rank: high

* Currently implemented mitigations:
    * The default setting for `RELOAD_SCRIPT_ELEMENTS` is `False`, which inherently mitigates the risk unless explicitly enabled.
    * Django-unicorn's documentation does not encourage or provide examples of using `<script>` tags within component templates for dynamic content, reducing the likelihood of developers unintentionally using this pattern.
    * Default HTML encoding in Unicorn applies to content within `<script>` tags, unless a developer explicitly uses `safe` to bypass it. However, as noted, `safe` can be misused, especially if developers are unaware of the risks associated with `<script>` tags and `RELOAD_SCRIPT_ELEMENTS`.

* Missing mitigations:
    * There are no explicit warnings or guidelines in the documentation advising against the use of `<script>` tags with user-controlled, `safe` content in Unicorn templates, particularly when `RELOAD_SCRIPT_ELEMENTS` is enabled. This lack of guidance increases the risk of developers unknowingly introducing this vulnerability.
    * Consideration should be given to removing or strongly discouraging the `RELOAD_SCRIPT_ELEMENTS` feature altogether, given its inherent security risks and limited legitimate use cases. Alternatively, if retained, its risks should be prominently documented, and usage discouraged.
    * Default enforcement of a Content Security Policy (CSP) is absent. Implementing a restrictive CSP would serve as a robust defense-in-depth measure, mitigating the impact of XSS even if `<script>` re-execution occurs due to misconfiguration or developer error.

* Preconditions:
    * The `RELOAD_SCRIPT_ELEMENTS` setting must be explicitly set to `True` in the Django settings file (`settings.py`). This is a non-default configuration.
    * A developer must use the `safe` Meta attribute or template filter within a Unicorn component template to mark a component property as safe for rendering.
    * User-controlled data must be embedded within an inline `<script>` tag inside a component template and marked as safe. This requires a specific, and typically discouraged, coding pattern by the developer.

* Source code analysis:
    1. **File: ..\django-unicorn\docs\source\custom-morphers.md** (from previous analysis)
        - Documents the `MORPHER.RELOAD_SCRIPT_ELEMENTS` setting, describing its function: "Whether script elements should be reloaded when a component is re-rendered. Defaults to `False`. Only available with the `"morphdom"` morpher." While documented, the security implications of enabling this setting are not explicitly highlighted.
    2. **File: ..\django-unicorn\docs\source\settings.md** (from previous analysis)
        - Provides a brief description of `RELOAD_SCRIPT_ELEMENTS`: "Whether script elements should be reloaded when a component is re-rendered. Defaults to `False`. Only available with the `"morphdom"` morpher." Similar to `custom-morphers.md`, it lacks security warnings.
    3. **File: ..\django-unicorn\components\unicorn_template_response.py** (from previous analysis)
        - `UnicornTemplateResponse.render` includes conditional logic to handle `RELOAD_SCRIPT_ELEMENTS` based on the `MORPHER` setting.
        - The code implements the reloading of script elements when this setting is true, which directly leads to the potential for re-execution of scripts and thus, XSS if those scripts contain malicious user input.

    **Vulnerability analysis:**
    If `RELOAD_SCRIPT_ELEMENTS` is set to `True`, and a developer incorporates `<script>` tags in Unicorn templates with `safe` user input (e.g., `<script>{{ user_script|safe }}</script>`), then during component updates, `morphdom` will re-insert and re-execute these `<script>` tags. If `user_script` originates from or includes malicious JavaScript, it will be re-run each time the component updates, leading to XSS. The vulnerability is a combination of enabling a less common setting and developers adopting an insecure templating practice.  Although not a default configuration, the potential for XSS and the non-obvious nature of the risk elevate its severity to high, especially for applications where developers might explore or misunderstand the implications of `RELOAD_SCRIPT_ELEMENTS`.

* Security test case:
    1. Enable `RELOAD_SCRIPT_ELEMENTS` in Django project's `settings.py`:
       ```python
       # settings.py
       UNICORN = {
           ...
           "MORPHER": {
               "NAME": "morphdom",
               "RELOAD_SCRIPT_ELEMENTS": True,
           }
           ...
       }
       ```
    2. Create a Unicorn component named `script_reload_xss` in `components/script_reload_xss.py`:
    ```python
    from django_unicorn.components import UnicornView

    class ScriptReloadXssView(UnicornView):
        unsafe_script = ""
        toggle = False

        class Meta:
            safe = ("unsafe_script",)
    ```
    3. Define the component's template at `templates/unicorn/script-reload-xss.html`:
    ```html
    <div>
        <button unicorn:click="$toggle('toggle')">Toggle</button>
        {% if toggle %}
            <input unicorn:model="unsafe_script" type="text" />
            <script>{{ unsafe_script|safe }}</script>
        {% endif %}
    </div>
    ```
    4. Create a Django view to render a template that includes the `script_reload_xss` component (similar to the previous test case's setup in `views.py`).
    5. Create a Django template `templates/script_reload_xss_test.html` to include the component (similar structure to `attribute_xss_test.html`).
    6. Configure `urls.py` to include the new view and Unicorn URLs.
    7. Start the Django development server.
    8. Open the `script_reload_xss_test` view in a browser.
    9. Click the "Toggle" button to reveal the input field and script block.
    10. Input the XSS payload into the text field: `alert('Script Reload XSS')`
    11. Click "Toggle" again to hide the input and script, then click "Toggle" a second time to re-show them. This action forces a component update and triggers script reload.
    12. Observe that an alert box with 'Script Reload XSS' appears again after toggling, demonstrating XSS due to the re-execution of the injected script.
