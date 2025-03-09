* Vulnerability Name: Cross-Site Scripting (XSS) vulnerability due to unsafe HTML attributes
* Description:
    1. An attacker can craft a malicious string that, when used as an attribute value in a Django template rendered by django-unicorn, will execute arbitrary JavaScript code in the victim's browser.
    2. This is possible because while django-unicorn by default HTML-encodes updated field values to prevent XSS in HTML tag content, this encoding is not consistently applied in all contexts, specifically within HTML attributes.
    3. An attacker can inject malicious JavaScript code through component properties that are used to dynamically generate HTML attributes in Django templates.
    4. When the component updates and the template is re-rendered, if these properties are not properly encoded, the injected JavaScript code will be executed in the user's browser via the HTML attribute.
* Impact:
    * Successful exploitation of this vulnerability allows an attacker to execute arbitrary JavaScript code in the context of the victim's browser.
    * This can lead to various malicious actions, including but not limited to:
        * Stealing user session cookies and hijacking user accounts.
        * Performing actions on behalf of the user without their knowledge or consent.
        * Defacing the web page or redirecting the user to malicious websites.
        * Phishing attacks by displaying fake login forms.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    * According to `changelog.md` - "Security fix: for CVE-2021-42053 to prevent XSS attacks". It is mentioned that responses will be HTML encoded going forward and to opt-out, the `safe` filter/attribute should be used.
    * `views.md` mentions "By default, `unicorn` HTML encodes updated field values to prevent XSS attacks. You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple."
    * The file `django_unicorn\utils.py` contains `sanitize_html` function which escapes HTML/XML special characters. However, this function is primarily used for JSON data within `<script>` tags and not consistently applied to HTML attribute values during template rendering.
* Missing Mitigations:
    * While django-unicorn includes HTML encoding for updated field values as a default mitigation, this is focused on the content within HTML tags. It does not appear to consistently apply HTML encoding to component properties used to dynamically generate HTML attributes.
    * Mitigation is missing to ensure that HTML encoding is automatically and consistently applied to component properties when they are used to dynamically set HTML attributes in Django templates.
    * There is no explicit documentation or code in the provided files confirming that attribute values are automatically encoded by default to prevent attribute-based XSS.
* Preconditions:
    * Application using django-unicorn is deployed and publicly accessible.
    * A component is designed such that its properties can influence HTML attributes in the rendered template.
    * An attacker can control or influence the data that populates these component properties, potentially through URL parameters, form inputs, or other means.
* Source Code Analysis:
    1. **`changelog.md` and `views.md`**: Indicate that django-unicorn has implemented HTML encoding as a security measure against XSS for tag content, but these documents do not explicitly mention attribute encoding. The `safe` Meta attribute allows developers to opt-out of encoding for specific fields, implying a default encoding for tag content.
    2. **`django_unicorn\utils.py`**: The `sanitize_html` function is available for HTML escaping, but its usage is limited. It is used in `UnicornTemplateResponse` to sanitize the `init` JSON data that is embedded within a `<script>` tag, as seen in `UnicornTemplateResponse.render` method.
    3. **`django_unicorn\components\unicorn_template_response.py`**: This file handles the rendering of the component template. The `UnicornTemplateResponse.render` method uses BeautifulSoup to parse and manipulate the HTML content. While it adds `unicorn:` attributes to the root element, it does not perform HTML encoding on dynamically generated attributes derived from component properties within the template itself. The `UnsortedAttributes` class is used as a formatter for BeautifulSoup, but it only preserves the order of attributes and does not apply any encoding. The `_desoupify` method simply converts the BeautifulSoup object back to a string without any encoding of attribute values.
    4. **`django_unicorn\templatetags\unicorn.py`**: The `unicorn` template tag is responsible for rendering components within Django templates. `UnicornNode.render` method orchestrates component creation and rendering by calling `UnicornView.create` and `UnicornView.render`. This process does not include explicit HTML attribute encoding for component properties being inserted into attributes within the template.
    5. **`django_unicorn\views\__init__.py`**: The `_process_component_request` function renders the component using `component.render(request=request)`. Before rendering, it checks for `safe_fields` defined in the component's Meta class and marks these fields as safe using `mark_safe`. This safety mechanism applies to the content within HTML tags, not to HTML attribute values. The function does not include any attribute encoding logic.
    6. **Analysis of New Files**: The newly provided files (`..\django-unicorn\tests\views\utils\test_construct_model.py`, `..\django-unicorn\tests\views\utils\test_set_property_from_data.py`, `..\django-unicorn\pyproject.toml`) are primarily focused on testing internal functionalities like model construction and property setting, and project configuration. They do not include any code related to template rendering or HTML attribute encoding.  These files do not introduce any new mitigations for the XSS vulnerability, nor do they reveal any new vulnerabilities related to XSS in HTML attributes. The tests confirm the functionalities described in the previous analysis but do not cover explicit attribute encoding for XSS prevention. Therefore, based on these new files, the assessment of the XSS vulnerability in HTML attributes remains unchanged.

    **Visualization**:
    ```
    [Django Template] --> {% unicorn component_name dynamic_attribute=component.property %} --> [Unicorn Template Tag] --> UnicornNode.render() --> UnicornView.create() --> UnicornView.render() --> UnicornTemplateResponse.render() --> BeautifulSoup parsing --> Attribute values from component.property inserted into HTML attributes (no encoding) --> _desoupify() --> [HTML Response]
    ```

    **Conclusion**: The source code analysis, including the newly provided test files and project configuration, consistently points to a lack of automatic HTML encoding for component properties when used in HTML attributes.  The existing vulnerability related to XSS in HTML attributes remains unmitigated based on the analyzed code.
* Security Test Case:
    1. Create a django-unicorn component named `attribute_xss` in your Django application.
    2. In `attribute_xss.py`, define a component view `AttributeXSSView` with a property `dynamic_attribute` initialized with a safe string, e.g., `dynamic_attribute = "safe_value"`.
    3. In `attribute_xss.html`, use this property to dynamically set an HTML attribute, for example:
        ```html
        <div id="vuln-div" data-attribute="{{ dynamic_attribute }}">
            Safe content here.
        </div>
        ```
    4. Create a Django view and template to include the `attribute_xss` component.
    5. Access the page in a browser and inspect the HTML source of `vuln-div`. Confirm that `data-attribute` is `safe_value`.
    6. Now, modify the `AttributeXSSView` to set `dynamic_attribute` to a malicious string containing JavaScript, such as: `dynamic_attribute = "><img src=x onerror=alert('XSS')>"`. You can simulate this data coming from an external source or directly modify the component property in the view for testing purposes.
    7. Refresh the page in the browser.
    8. **Expected Result (Vulnerability Present):** An alert box with 'XSS' should appear, indicating that the JavaScript code in `dynamic_attribute` was executed. Inspect the HTML source again; you should see the injected JavaScript within the `data-attribute`. For example, you might see `<div id="vuln-div" data-attribute="><img src=x onerror=alert('XSS')>">`.
    9. **Expected Result (Mitigation Present):** No alert box should appear. Inspect the HTML source and verify that the malicious string in `data-attribute` is HTML-encoded, preventing JavaScript execution. For example, `<div id="vuln-div" data-attribute="&gt;&lt;img src=x onerror=alert(&#x27;XSS&#x27;)&gt;">`.

This test case effectively verifies if django-unicorn properly encodes component properties when they are used within HTML attributes, thus preventing attribute-based XSS. Based on the source code analysis, the vulnerability is likely present, and this test case should confirm it. Further investigation and potentially more focused code review on template rendering and variable substitution within attributes are recommended to fully ascertain the scope of this vulnerability.
