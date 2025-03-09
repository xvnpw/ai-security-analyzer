- Vulnerability Name: Cross-Site Scripting (XSS) in Component Rendering

- Description:
  Django-unicorn renders component templates on the server-side and updates the DOM in the browser. When component properties are updated, django-unicorn serializes the component's data and sends it to the client. The client-side Javascript then uses this data to re-render parts of the DOM. If a component property that is used in a template is not properly sanitized, an attacker can inject malicious Javascript code into the property value. When the component is re-rendered, this malicious Javascript will be executed in the user's browser.

  Steps to trigger vulnerability:
  1. Create a django-unicorn component with a property that is rendered in the template without proper HTML escaping. For example, a component `VulnerableComponent` with property `unsafe_data` and template `vulnerable.html` containing `<div>{{ unsafe_data }}</div>`.
  2. In the component's view, create an action method that updates the `unsafe_data` property with user-controlled input. For example:
     ```python
     def set_unsafe_data(self, data):
         self.unsafe_data = data
     ```
  3. In the template, add an input field bound to the `unsafe_data` property and a button to trigger the `set_unsafe_data` action. For example:
     ```html
     <input unicorn:model="unsafe_data">
     <button unicorn:click="set_unsafe_data(unsafe_data)">Set Data</button>
     ```
  4. An attacker can then input malicious Javascript code into the input field, such as `<img src=x onerror=alert('XSS')>`, and click the button.
  5. The `set_unsafe_data` action will be called, updating the `unsafe_data` property with the malicious payload.
  6. Django-unicorn will re-render the component and send the updated HTML to the client.
  7. The client-side Javascript will update the DOM with the re-rendered HTML, including the malicious Javascript code.
  8. The injected Javascript code will be executed in the user's browser when the DOM is updated.

- Impact:
  Cross-site scripting (XSS) allows an attacker to execute arbitrary Javascript code in the victim's browser within the context of the application. This can lead to various malicious activities, including:
    - Account takeover: Stealing session cookies or credentials to impersonate the user.
    - Data theft: Accessing sensitive information displayed on the page or making API requests on behalf of the user.
    - Defacement: Altering the appearance of the web page.
    - Redirection: Redirecting the user to a malicious website.
    - Further attacks: Using the compromised context to launch other attacks against the user or the application.

- Vulnerability Rank: critical

- Currently implemented mitigations:
  Django-unicorn HTML encodes updated field values by default to prevent XSS attacks. This is mentioned in `changelog.md` for version 0.36.0 and `docs\source\views.md`.
  However, developers can explicitly mark a field or template variable as `safe` to bypass HTML encoding.

- Missing mitigations:
  While django-unicorn defaults to HTML encoding, it relies on developers to not explicitly bypass this protection when rendering user-controlled data. There is no built-in Content Security Policy (CSP) or other robust mechanism to prevent XSS if developers use `safe` incorrectly.

- Preconditions:
  - The application must be using django-unicorn.
  - A component must render user-controlled data without proper HTML escaping, either by using `safe` filter in template or `safe` Meta attribute in component view.
  - An action method must update the vulnerable component property with user-controlled input.

- Source code analysis:
  - `django_unicorn\views\__init__.py`: The `_process_component_request` function handles component updates.
  - In `_process_component_request`, the component is re-rendered with `component.render(request=request)`.
  - The `rendered_component` is then sent back to the client in the JSON response.
  - `django_unicorn\components\unicorn_template_response.py`: The `UnicornTemplateResponse.render` method is responsible for rendering the component template.
  - In `UnicornTemplateResponse.render`, `soup = BeautifulSoup(content, features="html.parser")` is used to parse the template.
  - The template is rendered using Django's template engine, which by default HTML-escapes variables.
  - However, if the `safe` template filter or `safe` Meta attribute is used, the output is not HTML-encoded.
  - If a component property is marked as `safe` in `Meta.safe` or `safe` filter is used in template, the value is rendered without HTML encoding:
    - `docs\source\views.md`: "By default, `unicorn` HTML encodes updated field values to prevent XSS attacks. You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple." and "A context variable can also be marked as `safe` in the template with the normal Django template filter."
  - If a developer incorrectly uses `safe` filter or attribute with user-controlled data, XSS vulnerability can be introduced.

- Security Test Case:
  1. Create a Django project and install django-unicorn.
  2. Create a django-unicorn component named `xss_component` in an app named `vulntest`.
  3. Create component view `vulntest\components\xss_component.py`:
     ```python
     from django_unicorn.components import UnicornView

     class XssComponentView(UnicornView):
         unsafe_data = ""
     ```
  4. Create component template `vulntest\templates\unicorn\xss_component.html`:
     ```html
     <div>
         <div id="vuln-target" >{{ unsafe_data|safe }}</div>
         <input type="text" unicorn:model.defer="unsafe_data">
         <button unicorn:click="$refresh">Update Data</button>
     </div>
     ```
     **Note:** `unsafe_data|safe` filter is used to explicitly disable HTML escaping.
  5. Create a Django template to include the component, e.g., `vulntest\templates\index.html`:
     ```html
     {% load unicorn %}
     <html>
     <head>
         {% unicorn_scripts %}
     </head>
     <body>
         {% csrf_token %}
         {% unicorn 'xss-component' %}
     </body>
     </html>
     ```
  6. Create a Django view and URL to render `index.html`.
  7. Run the Django development server.
  8. Open the application in a browser and navigate to the URL for `index.html`.
  9. In the input field, enter the following payload: `<img src=x onerror=alert('XSS')>`.
  10. Click the "Update Data" button.
  11. Observe that an alert box with "XSS" is displayed, indicating that the Javascript code was executed.
  12. Examine the HTML source code in browser developer tools and observe that the `unsafe_data` in `div#vuln-target` is rendered without HTML encoding, containing the injected Javascript payload `<img src=x onerror=alert('XSS')>`.
