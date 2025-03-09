### Vulnerability List for django-unicorn project:

* Vulnerability Name: Cross-Site Scripting (XSS) vulnerability due to unsafe HTML attribute injection

* Description:
    1. An attacker can manipulate component's properties, particularly string properties, to inject malicious HTML attributes into the rendered HTML.
    2. When a component is re-rendered due to user interaction or polling, the injected HTML attributes are included in the server response.
    3. The JavaScript code in `django-unicorn` uses `morphdom` to update the DOM by diffing the old and new HTML.
    4. If the injected HTML attributes are placed in a way that `morphdom` interprets them as new attributes rather than part of text content, these attributes will be directly injected into the DOM.
    5. If the injected attributes contain JavaScript code (e.g., `onload`, `onerror`, `onmouseover`), they will be executed in the user's browser, leading to XSS.

* Impact:
    - Critical
    - Successful exploitation allows an attacker to execute arbitrary JavaScript code in the context of the user's browser when they interact with the affected component.
    - This can lead to session hijacking, account takeover, defacement, redirection to malicious sites, or other malicious actions.

* Vulnerability Rank: critical

* Currently Implemented Mitigations:
    - HTML encoding for updated field values is mentioned in `docs\source\views.md` under "Meta -> safe", suggesting that by default, responses are HTML encoded to prevent XSS.
    - The `safe` Meta option allows developers to opt-in to disable HTML encoding for specific fields. This is intended for cases where developers want to return raw HTML, but it also inadvertently opens the door for attribute injection if used carelessly.

* Missing Mitigations:
    - The current HTML encoding mitigation appears to be insufficient to prevent attribute injection. While content within HTML tags might be encoded, HTML attributes themselves are not properly sanitized against injection attacks. DOM diffing libraries like `morphdom`, used for efficiency, directly apply changes to the DOM, including potentially malicious attributes.
    - There is no explicit input sanitization or attribute encoding mechanism in place to prevent injection of malicious HTML attributes. The `sanitize_html` function in `django_unicorn\utils.py` is used for escaping HTML in JSON, not for attribute encoding during HTML rendering.

* Preconditions:
    - The application must be using `django-unicorn` and have components with string properties that are rendered into HTML attributes.
    - An attacker needs to find a component property that is reflected into HTML attributes without sufficient sanitization.
    - The developer must use template syntax that allows injecting properties as HTML attributes, for example using `{{ property_name }}` directly within an HTML tag.

* Source Code Analysis:
    1. **`django_unicorn\components\unicorn_view.py`**: This file defines the core `UnicornView` class. The `get_frontend_context_variables` method serializes component data to JSON. This data is then used to update the frontend. While there's HTML encoding mentioned in documentation, the code itself doesn't show explicit attribute sanitization. The `_set_property` method is responsible for updating component attributes but focuses on type casting and lifecycle hooks, not sanitization.

    2. **`django_unicorn\components\unicorn_template_response.py`**: This file handles rendering the component's template. The `UnicornTemplateResponse.render` method uses `BeautifulSoup` to parse and modify the HTML. Crucially, it sets attributes like `unicorn:id`, `unicorn:name`, `unicorn:data`, and `unicorn:calls` directly on the root element. However, it does not perform any attribute sanitization on user-controlled data that might end up in attributes. The `_desoupify` method simply converts the `BeautifulSoup` object back to a string, using `UnsortedAttributes` formatter which preserves attribute order but doesn't sanitize them.

    ```python
    # django_unicorn\components\unicorn_template_response.py
    class UnicornTemplateResponse(TemplateResponse):
        # ...
        @timed
        def render(self):
            # ...
            soup = BeautifulSoup(content, features="html.parser")
            root_element = get_root_element(soup)
            # ...
            root_element["unicorn:id"] = self.component.component_id
            root_element["unicorn:name"] = self.component.component_name
            root_element["unicorn:key"] = self.component.component_key
            root_element["unicorn:checksum"] = checksum
            root_element["unicorn:data"] = frontend_context_variables # Data is added as attribute
            root_element["unicorn:calls"] = orjson.dumps(self.component.calls).decode("utf-8") # Calls are added as attribute
            # ...
            rendered_template = UnicornTemplateResponse._desoupify(soup)
            # ...
            return response

        @staticmethod
        def _desoupify(soup):
            soup.smooth()
            return soup.encode(formatter=UnsortedAttributes()).decode("utf-8") # No sanitization here
    ```

    3. **`django_unicorn\utils.py`**: This file contains utility functions, including `sanitize_html`. However, `sanitize_html` is used to escape HTML for JSON serialization (specifically for `json_script` in Django templates), not for general HTML attribute sanitization. It's not used in the component rendering or attribute setting process.

    4. **`django_unicorn\views\__init__.py` and `django_unicorn\views\utils.py`**: These files handle the view logic and property setting.  `set_property_from_data` in `django_unicorn\views\utils.py` updates component properties based on incoming data, but it focuses on type casting and model handling, not output sanitization. The main view logic in `django_unicorn\views\__init__.py` orchestrates component creation, action handling, and rendering, but it doesn't introduce any attribute sanitization. The file `django_unicorn\views\action_parsers\utils.py` containing function `set_property_value` is responsible for setting component properties, and it also lacks any sanitization of property values before setting them on the component.

    ```python
    # django_unicorn\views\action_parsers\utils.py
    def set_property_value(
        component: UnicornView,
        property_name: Optional[str],
        property_value: Any,
        data: Optional[Dict] = None,
        call_resolved_method=True,  # noqa: FBT002
    ) -> None:
        """
        Sets properties on the component.
        ...
        """

        # ... (logic for setting property value)

        setattr(component_or_field, property_name_part, property_value)

        # ...
    ```

    5. **`morphdom`**: While not directly in the provided files, `morphdom` is mentioned in `docs\source\architecture.md` (from previous analysis) and confirmed by `get_morpher_settings()` in `django_unicorn\settings.py` which defaults to `morphdom`. `morphdom` efficiently updates the DOM by making minimal changes, which can include directly injecting attributes if they are present in the server response. This behavior, while performant, bypasses any browser-side attribute sanitization that might otherwise occur if the HTML was re-parsed from scratch.

* Security Test Case:
    1. Create a Django Unicorn component named `xss_attribute`.
    2. In `components\xss_attribute.py`, define a component view `XssAttributeView` with a string property `attribute_value` initialized to an empty string.
    ```python
    # components\xss_attribute.py
    from django_unicorn.components import UnicornView

    class XssAttributeView(UnicornView):
        attribute_value = ""
    ```
    3. In `templates\unicorn\xss-attribute.html`, create a template that renders the `attribute_value` as an HTML attribute directly using template interpolation:
    ```html
    # templates\unicorn\xss-attribute.html
    <div>
        <input type="text" unicorn:model="attribute_value" id="attributeInput">
        <div id="test-div" {{ attribute_value }}></div> <--- Vulnerable attribute injection point
    </div>
    ```
    4. Create a Django view and template to include the `xss_attribute` component.
    ```python
    # views.py
    from django.shortcuts import render
    from django.views.generic import TemplateView
    from django.urls import path, include
    from . import views

    class HomeView(TemplateView):
        template_name = 'home.html'

    urlpatterns = [
        path('', views.HomeView.as_view(), name='home'),
        path("unicorn/", include("django_unicorn.urls")),
    ]
    ```
    ```html
    {# templates\home.html #}
    {% load unicorn %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        {% unicorn 'xss-attribute' %}
    </body>
    </html>
    ```
    5. Run the Django development server.
    6. Open the application in a web browser and navigate to the page containing the `xss_attribute` component.
    7. In the input field, enter the following malicious payload: `onload="alert('XSS')"`.
    8. Click outside the input field or trigger an update to send the `attribute_value` to the server (e.g., by pressing Tab or Enter).
    9. Observe if an alert box with "XSS" is displayed when the component re-renders. If the alert box appears, it confirms that the JavaScript code injected through the attribute was executed, demonstrating a successful XSS vulnerability.

    10. **Expected Result**: An alert box with "XSS" should appear, indicating that the injected `onload` attribute was successfully added to the `div` element and executed by the browser, proving the XSS vulnerability.

* Vulnerability Status: Valid and not mitigated based on the provided files and analysis.
