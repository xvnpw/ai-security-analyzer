### 1. Reflected Cross-Site Scripting (XSS) in Component Property Rendering

* Description:
    1. An attacker can inject malicious JavaScript code into a component property.
    2. When the component is rendered, the injected JavaScript code is included in the HTML output without proper sanitization.
    3. If a user interacts with the rendered component or the page containing it, the malicious JavaScript code will be executed in the user's browser.

* Impact:
    * Account takeover: If the application uses cookies for session management, the attacker can steal user cookies and hijack user sessions.
    * Data theft: The attacker can steal sensitive information such as user credentials, personal data, or application data.
    * Website defacement: The attacker can modify the content of the web page, redirect users to malicious websites, or display misleading information.
    * Malicious actions: The attacker can perform actions on behalf of the user, such as making unauthorized purchases, changing account settings, or spreading malware.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    * The documentation mentions in `views.md#safe`: "By default, `unicorn` HTML encodes updated field values to prevent XSS attacks." and "You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple." This suggests that output is encoded by default unless `safe` is used.
    * Source code analysis of `django_unicorn\components\unicorn_template_response.py` and `django_unicorn\templatetags\unicorn.py` shows that Django's template rendering engine is used, which by default applies HTML escaping to variables rendered in templates. This provides a base level of protection against XSS when developers use `{{ component.property }}` in templates.
    * Code analysis of `django_unicorn\views\__init__.py` confirms that for attributes marked as `safe` in the component's `Meta` class, `mark_safe` is applied to the value right before rendering. This is explicitly done in the `_process_component_request` function.
    * Tests in `tests/test_utils.py` include a function named `sanitize_html`, however, source code analysis shows this function is used for sanitizing data used to generate checksums, primarily removing `<script>` tags. It is **not** used for general HTML sanitization of component output to prevent XSS.

* Missing Mitigations:
    * While default HTML encoding is in place, it's insufficient in cases where developers need to render HTML content and explicitly use the `safe` attribute in the component's `Meta` class to bypass encoding. There is no enforced input sanitization to be used in conjunction with `safe`.
    * The documentation's suggestion to use `safe` for specific fields implies a mitigation, but it does not provide guidance on *how* to safely use it. Developers might misunderstand `safe` as a general sanitization mechanism, leading to vulnerabilities if they use it without properly sanitizing the input themselves.
    * There is no clear mechanism or recommendation within the framework to sanitize user inputs *before* they are assigned to component properties. The current mitigation relies solely on output encoding, which can be bypassed by design using `safe`.

* Preconditions:
    * An attacker needs to find a component property that is rendered directly in the template and can be influenced by user input (e.g., through URL parameters, form inputs, or other means of data injection).
    * The developer must have either:
        * Explicitly marked the vulnerable property as `safe` in the component's `Meta` class without sanitizing the input.
        * Used `safe` filters in the template itself, e.g., `{{ component.property|safe }}` without sanitizing the input in the component.

* Source Code Analysis:
    1. **`django_unicorn\components\unicorn_view.py` and `django_unicorn\components\unicorn_template_response.py`:**
        * The `render` method in `UnicornView` uses `render_to_response` which eventually utilizes Django's template engine via `UnicornTemplateResponse`.
        * `UnicornTemplateResponse` inherits from `TemplateResponse` and uses Django's template backend for rendering in its `render` method.
        * Django's template engine automatically HTML-encodes variables by default, providing initial protection.
        * The component's context, built in `UnicornView.get_context_data`, includes component attributes and methods, which are then available in the template for rendering.
        * **Visualization:**
        ```
        UserInput --> Component Property (UnicornView._set_property via django_unicorn/views/action_parsers/utils.set_property_value called by django_unicorn/views/action_parsers/sync_input.handle) --> Template Context (UnicornView.get_context_data) --> Django Template Rendering (UnicornTemplateResponse.render) --> HTML Output (with default HTML encoding)
        ```
    2. **`django_unicorn\views\action_parsers\sync_input.py` and `django_unicorn\views\action_parsers\utils.py`:**
        * `django_unicorn\views\action_parsers\sync_input.py` handles the `syncInput` action type, which is used to update component properties based on user input.
        * The `handle` function in `sync_input.py` directly calls `set_property_value` from `django_unicorn\views\action_parsers\utils.py` to set the property value.
        * `set_property_value` sets the property without any sanitization of the `property_value`.
    3. **`views.md#safe` documentation:**
        * Documentation explicitly mentions `safe` to bypass HTML encoding, highlighting the risk if misused.
    4. **`changelog.md` version 0.36.0 (from previous context):**
        * Security fix in version 0.36.0 indicates a prior vulnerability related to XSS and the introduction of default HTML encoding, reinforcing the importance of output encoding as a primary mitigation but also the risk of bypassing it.
    5. **`tests/views/test_process_component_request.py`:**
        * Contains test cases (`test_html_entities_encoded`, `test_safe_html_entities_not_encoded`) that explicitly demonstrate the default HTML encoding and how the `safe` attribute bypasses it.
    6. **`django_unicorn\views\__init__.py`:**
        * In the `_process_component_request` function, the code iterates through `safe_fields` (defined by `Meta.safe` in component) and applies `mark_safe` to the corresponding component attribute *before* rendering. This confirms that `safe` fields bypass default HTML encoding, and the framework relies on developers to handle sanitization for these fields.

* Security Test Case:
    1. Create a Django Unicorn component named `XSSPropertyComponent` with a property `unsafe_property` initialized from a GET request parameter.
    2. Component code (`example/unicorn/components/xss_property.py`):
    ```python
    from django_unicorn.components import UnicornView

    class XSSPropertyComponentView(UnicornView):
        template_name = "unicorn/xss-property.html"
        unsafe_property = ""

        def mount(self):
            self.unsafe_property = self.request.GET.get("unsafe_property", "")
    ```
    3. Template code (`example/unicorn/templates/xss-property.html`):
    ```html
    <div>
        <p>Unsafe Property: {{ unsafe_property }}</p>
    </div>
    ```
    4. Access the page with a crafted URL: `/?unsafe_property="<script>alert('XSS-property-default-encoding')</script>"`.
    5. Observe if the `alert('XSS-property-default-encoding')` does *not* execute, verifying default encoding. The output in the HTML source should be HTML-encoded script tags: `<p>Unsafe Property: &lt;script&gt;alert('XSS-property-default-encoding')&lt;/script&gt;</p>`.
    6. Modify the component to mark `unsafe_property` as `safe` in `Meta` class:
    ```python
    from django_unicorn.components import UnicornView

    class XSSPropertyComponentView(UnicornView):
        template_name = "unicorn/xss-property.html"
        unsafe_property = ""

        class Meta:
            safe = ("unsafe_property",)

        def mount(self):
            self.unsafe_property = self.request.GET.get("unsafe_property", "")
    ```
    7. Repeat step 4. Observe if the `alert('XSS-property-default-encoding')` *executes* when the page loads. This confirms that `safe` bypasses default encoding and can lead to XSS if the property is not sanitized. The output in the HTML source should now contain the raw script tags: `<p>Unsafe Property: <script>alert('XSS-property-default-encoding')</script></p>`.

### 2. Reflected Cross-Site Scripting (XSS) through Action Method Arguments

* Description:
    1. An attacker can inject malicious JavaScript code as arguments to a component's action method, potentially via URL manipulation or intercepted requests.
    2. If these arguments are not properly sanitized *before* being used in rendering within the action method or subsequently rendered in the component template after the action is processed, XSS can occur.
    3. This is especially risky if action methods dynamically construct HTML or redirect URLs using unsanitized arguments.

* Impact:
    * Similar to vulnerability 1, this can lead to account takeover, data theft, website defacement, and malicious actions depending on the context and how the injected code is used.

* Vulnerability Rank: Medium

* Currently Implemented Mitigations:
    * The framework focuses on output encoding of component properties rendered in templates, as discussed in Vulnerability 1. However, this mitigation does not automatically extend to arguments passed to action methods and how they are processed *within* the component's Python code.
    * `django_unicorn\call_method_parser.py` is responsible for parsing arguments from the request. Code analysis of `tests\call_method_parser\test_parse_args.py` shows that the parser correctly handles various data types, but does not perform any sanitization.
    * `django_unicorn\views\action_parsers\call_method.py` and `django_unicorn\views\__init__.py` handle `callMethod` actions. Code analysis of `django_unicorn\views\__init__.py` in `_process_component_request` and `_handle_queued_component_requests` functions shows that `call_method.handle` is called to process these actions, and arguments are passed to the component method without sanitization.
    * Tests in `tests/test_utils.py` include a function named `sanitize_html`, however, source code analysis shows this function is used for sanitizing data used to generate checksums, primarily removing `<script>` tags. It is **not** used for general HTML sanitization of action method arguments or component output to prevent XSS.

* Missing Mitigations:
    * **Input sanitization for action method arguments is missing.** The project lacks a built-in mechanism to automatically sanitize or validate arguments passed to action methods. Developers are responsible for manually sanitizing these arguments within their component code if they are used in a way that could lead to XSS.
    * **Documentation should explicitly warn against using action method arguments directly in template rendering or in operations that can lead to reflected output without proper sanitization.** While the documentation provides guidance on using `safe` for component properties, it does not adequately address the risks associated with action method arguments.

* Preconditions:
    * An attacker needs to identify an action method that processes arguments and where these arguments, directly or indirectly, influence rendered output or trigger unsafe operations.
    * The action method must not sanitize its arguments before using them in a way that could lead to XSS. This includes cases where arguments are:
        * Directly rendered in the template after being processed by the action method.
        * Used to construct HTML content dynamically within the action method, which is then rendered.
        * Used to construct URLs for redirects or other dynamic operations that involve rendering or outputting user-controlled data.

* Source Code Analysis:
    1. **`django_unicorn\call_method_parser.py`:**
        * Analyzed `eval_value` function (used by `parse_call_method_name`). It focuses on parsing the method arguments from a string, converting arguments to appropriate Python types (int, dict, string, etc.).
        * No sanitization or validation is performed on the arguments during parsing. The parsed arguments are returned as-is.
        * This means that if malicious JavaScript code is passed as an argument, it will be parsed and passed to the component method without any modification.
        * Code analysis of `tests\call_method_parser\test_parse_args.py` confirms the parsing logic and lack of sanitization.
    2. **`example components and documentation`:**
        * Reviewed `example\unicorn\components` and documentation (actions.md).
        * Found no examples or recommendations for sanitizing action method arguments.
        * The example in `actions.md#passing-arguments` demonstrates passing arguments but does not include any sanitization steps, implicitly suggesting that arguments are used directly.
    3. **`django_unicorn\views\action_parsers\call_method.py`:**
        * `django_unicorn\views\action_parsers\call_method.py` handles the `callMethod` action.
        * The `handle` function in `call_method.py` calls `_call_method_name` to invoke the component method.
        * `_call_method_name` processes arguments and passes them directly to the component method without any sanitization.
    4. **`django_unicorn\views\__init__.py`:**
        * Code analysis of `_process_component_request` and `_handle_queued_component_requests` functions confirms that `call_method.handle` is invoked to process `callMethod` actions and that arguments are passed to the component method without sanitization.

* Security Test Case:
    1. Create a Django Unicorn component named `XSSActionArgComponent` with an action method `display_arg(self, arg)`.
    2. Component code (`example/unicorn/components/xss_action_arg.py`):
    ```python
    from django_unicorn.components import UnicornView
    from django.utils.html import escape

    class XSSActionArgComponentView(UnicornView):
        template_name = "unicorn/xss-action-arg.html"
        output = ""

        def display_arg(self, arg):
            self.output = arg # Vulnerable: arg is not sanitized

        def display_arg_sanitized(self, arg):
            self.output = escape(arg) # Mitigated: arg is sanitized

    ```
    3. Template code (`example/unicorn/templates/xss-action-arg.html`):
    ```html
    <div>
        <button unicorn:click="display_arg(user_input)">Display Input (Unsanitized)</button>
        <button unicorn:click="display_arg_sanitized(user_input)">Display Input (Sanitized)</button>
        <p>Output: {{ output }}</p>
        <input unicorn:model.lazy="user_input" type="text" value="" />
    </div>
    ```
    4. In the base template where this component is used, add a context variable `user_input` that can be controlled by the attacker, for example, from a GET parameter:
    ```python
    def base_view(request):
        user_input = request.GET.get("user_input", "")
        return render(request, "base.html", {"user_input": user_input})
    ```
    5. Access the page with a URL that sets `user_input` to malicious JavaScript: `/?user_input="<script>alert('XSS-Arg-Unsanitized')</script>"`.
    6. Click the "Display Input (Unsanitized)" button. Observe if `alert('XSS-Arg-Unsanitized')` *executes*. This confirms XSS vulnerability through unsanitized action method arguments. The output in the HTML source should be: `<p>Output: <script>alert('XSS-Arg-Unsanitized')</script></p>`.
    7. Click the "Display Input (Sanitized)" button. Observe if `alert('XSS-Arg-Sanitized')` does *not* execute. The output in the HTML source should be HTML-encoded: `<p>Output: &lt;script&gt;alert(&#39;XSS-Arg-Sanitized&#39;)&lt;/script&gt;</p>`. This demonstrates the mitigation when `escape` is used within the action method.
    8. Remove the `escape` function from the `display_arg_sanitized` method in the component and repeat step 7, clicking "Display Input (Sanitized)". Observe if `alert('XSS-Arg-Sanitized')` now *executes*, confirming that without sanitization, even methods with "_sanitized" in their name are vulnerable if not properly implemented.
