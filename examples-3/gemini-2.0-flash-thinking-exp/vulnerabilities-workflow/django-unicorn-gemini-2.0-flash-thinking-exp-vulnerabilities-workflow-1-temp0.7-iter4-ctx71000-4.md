### Vulnerability List for django-unicorn project:

* Vulnerability Name: Reflected Cross-Site Scripting (XSS) in Component Rendering

* Description:
    1. An attacker crafts a malicious URL or input that contains JavaScript code.
    2. A user visits a page that includes a Django Unicorn component.
    3. The Django Unicorn component renders user-provided data, which is derived from URL parameters, form inputs, or component properties updated by user actions, directly into the HTML template without proper HTML encoding. This includes data used to update component properties via mechanisms like `set_property_from_data` which handles various data types including models and querysets.
    4. The user's browser executes the injected JavaScript code, as it is treated as part of the web page.

* Impact:
    - An attacker can execute arbitrary JavaScript code in the victim's browser.
    - This can lead to various malicious actions, including:
        - Account hijacking by stealing session cookies or credentials.
        - Defacement of the website.
        - Redirection to malicious websites.
        - Data theft by accessing sensitive information on the page.
        - Performing actions on behalf of the user without their consent.

* Vulnerability Rank: high

* Currently implemented mitigations:
    - Based on the changelog for version 0.36.0, django-unicorn implemented HTML encoding for responses to prevent XSS attacks.
    - Version 0.36.1 mentions "More complete handling to prevent XSS attacks".
    - Version 0.29.0 mentions "Sanitize initial JSON to prevent XSS".
    - The documentation for views mentions `Meta.safe` to explicitly allow a field to be returned without encoding, implying default encoding is in place.
    - The code in `django_unicorn\utils.py` includes `sanitize_html` function which escapes HTML/XML special characters for JSON output. This function is used to sanitize data before embedding it in `<script>` tags, as seen in `django_unicorn\tests\test_utils.py` and `django_unicorn\components\unicorn_template_response.py`.
    - `sanitize_html` is used in `django_unicorn\components\unicorn_template_response.py` when creating `<script>` tags for component initialization data, specifically for `json_tag.string`. This is intended to protect against XSS when embedding component data in the initial HTML.
    - Tests in `django_unicorn\tests\views\test_process_component_request.py` like `test_html_entities_encoded` demonstrate that by default, HTML entities are encoded when component properties are rendered, suggesting a degree of automatic HTML encoding is active.

* Missing mitigations:
    - While HTML encoding and sanitization are mentioned and partially implemented, it's crucial to verify that HTML encoding is consistently and effectively applied across all scenarios where user-provided data or component properties are rendered in templates, beyond just JSON within `<script>` tags.
    - It needs to be confirmed that all dynamic content rendered within component templates is properly HTML-encoded by default, preventing XSS in various contexts, not just within `<script>` tags and initial component data. This includes scenarios where component properties are updated via mechanisms like `set_property_from_data`, especially when handling complex data types like models and querysets.
    - The usage of `Meta.safe` needs further investigation to understand the scope and security implications of bypassing default encoding. Developers should be clearly guided on the risks of disabling HTML encoding and when it is appropriate to use it. There should be clear documentation emphasizing the security risks of disabling HTML encoding with `Meta.safe` and guidelines on when and how to use it safely.
    - Deeper analysis is required to confirm if Django's template engine's auto-escaping is consistently applied within Django Unicorn components, especially when rendering variables derived from user interactions or URL parameters directly within templates.

* Preconditions:
    1. A Django Unicorn component is designed to display dynamic data, which can be influenced by user input or component state changes, within its template.
    2. The component's view logic or template rendering process does not consistently HTML-encode this dynamic data before inserting it into the HTML response. This includes data set via `set_property_from_data`, especially for model and queryset properties.
    3. An attacker can find a way to inject malicious JavaScript code into the data that is processed and rendered by the component (e.g., through URL parameters, form inputs, or by manipulating component properties via actions).

* Source code analysis:
    - `django_unicorn\utils.py` contains `sanitize_html` function, which escapes HTML/XML special characters. This function is explicitly used for sanitizing JSON data, as seen in `django_unicorn\components\unicorn_template_response.py`.
    - In `django_unicorn\components\unicorn_template_response.py`, the `render` method uses `BeautifulSoup` to process the template. While `BeautifulSoup` itself does not automatically encode HTML when parsing or modifying, Django's template engine, when used correctly, should apply auto-escaping. The key is to verify if the variables passed to the template context are being escaped by Django's template engine before being rendered in the HTML output.
    - The `get_frontend_context_variables()` method in `django_unicorn\components\unicorn_view.py` serializes component data into JSON. This data is included as `unicorn:data` attribute and potentially used in `<script>` tags. The `sanitize_html` function is used when embedding this JSON data in `<script>` tags, as shown in `django_unicorn\components\unicorn_template_response.py`.
    - The test `test_safe_html_entities_not_encoded` in `django_unicorn\tests\views\test_process_component_request.py` and the existence of `Meta.safe` in `django_unicorn\components\unicorn_view.py` indicates a mechanism to bypass the default HTML encoding. This is further supported by the `test_html_entities_encoded` which demonstrates the default encoding behavior.
    - The test cases in `django_unicorn\tests\components\test_unicorn_template_response.py` like `test_desoupify` show that the rendered component HTML is processed and manipulated using `BeautifulSoup`. It is important to ensure that this processing does not inadvertently bypass or weaken HTML encoding in any way.
    - The file `django_unicorn\views\utils.py` and tests in `django_unicorn\tests\views\utils\test_set_property_from_data.py` reveal the `set_property_from_data` function. This function is responsible for updating component properties based on data received from the frontend, handling various data types including strings, integers, datetimes, lists, models, and querysets. If the data processed by `set_property_from_data` and subsequently rendered in templates is not consistently HTML-encoded, it could be a source of XSS vulnerabilities.
    - The file `django_unicorn\typer.py` and tests in `django_unicorn\tests\views\utils\test_construct_model.py` show the `_construct_model` function. This function constructs Django model instances from dictionaries. If the input data for `_construct_model` is attacker-controlled and model fields are rendered without encoding, it can lead to XSS.
    - **Visualization:**
        ```
        User Input (e.g., URL parameter, Form Input, Component Action Data) --> set_property_from_data() --> Component Property (including Model/Queryset) --> Template Context --> Template Rendering --> HTML Output --> User Browser
                                                                                                                              ^
                                                                                                                              |
                                                                                                      Check for HTML Encoding here. Is it always applied by default for all data types and contexts?
        ```
    - Further investigation (in future analysis with more files) is needed to confirm:
        - If Django's template engine auto-escaping is consistently applied to all variables rendered in component templates, especially those derived from user input and updated via `set_property_from_data`, including model and queryset data.
        - The exact scope and implications of using `Meta.safe` to disable HTML encoding.
        - If there are any template rendering scenarios or code paths within Django Unicorn components where data might be rendered without proper HTML encoding by default, potentially leading to XSS vulnerabilities, especially when handling complex data types like models and querysets updated via `set_property_from_data` and constructed by `_construct_model`.

* Security test case:
    1. Create a simple Django project with django-unicorn installed and configured.
    2. Create a Django Unicorn component named `xss_test_property`.
    3. In the `xss_test_property` component's view (`xss_test_property.py`), define a public property `user_input` initialized to an empty string:
    ```python
    # xss_test_property.py
    from django_unicorn.components import UnicornView

    class XssTestPropertyView(UnicornView):
        user_input: str = ""

        def mount(self):
            if "user_input" in self.request.GET:
                self.user_input = self.request.GET["user_input"]
    ```
    4. Create the component's template (`xss_test_property.html`) to render the `user_input` property directly:
    ```html
    <!-- xss_test_property.html -->
    <div>
        <p>User Input: {{ user_input }}</p>
    </div>
    ```
    5. Create a Django view that includes the `xss_test_property` component in a template:
    ```python
    # views.py
    from django.shortcuts import render

    def xss_property_view(request):
        return render(request, 'xss_property_template.html')
    ```
    ```html
    <!-- xss_property_template.html -->
    {% load unicorn %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        {% unicorn 'xss-test-property' %}
    </body>
    </html>
    ```
    6. In `urls.py`, add paths to the `xss_property_view`:
    ```python
    # urls.py
    from django.urls import path, include
    from .views import xss_property_view

    urlpatterns = [
        path('xss_property/', xss_property_view, name='xss_property_view'),
        path("unicorn/", include("django_unicorn.urls")),
    ]
    ```
    7. Run the Django development server.
    8. Access the `xss_property_view` in a web browser with a malicious payload in the `user_input` GET parameter, for example: `/xss_property/?user_input=<script>alert("XSS from property");</script>`.
    9. **Expected Result (Vulnerable):** If an alert box with "XSS from property" appears, it indicates that the JavaScript code from the `user_input` GET parameter was executed, confirming a reflected XSS vulnerability when rendering component properties.
    10. **Expected Result (Mitigated):** If the alert box does not appear and instead, the raw HTML `<script>alert("XSS from property");</script>` is displayed as text on the page, it suggests that HTML encoding is working to mitigate basic XSS in this property rendering scenario. Further testing with different contexts, user interactions, and data sources within components is needed to ensure complete mitigation.
