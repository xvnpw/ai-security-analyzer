- Reflected Cross-Site Scripting (XSS) via component method arguments

Description:
An attacker can trigger a reflected Cross-Site Scripting (XSS) vulnerability by injecting malicious Javascript code as arguments to component methods called using `Unicorn.call()`. When these arguments are rendered in the component's template without proper HTML encoding, the injected script can be executed in the victim's browser. This vulnerability arises because while Django Unicorn implements HTML encoding for component fields updated via `unicorn:model`, it does not enforce consistent HTML encoding for arguments passed directly to Javascript functions through `Unicorn.call()` when these arguments are subsequently rendered in the component template.

Step-by-step trigger:
1. An attacker crafts a URL or manipulates the application state to allow execution of Javascript code in the browser's console.
2. The attacker uses the browser's developer console to execute Javascript code that calls a Django Unicorn component method using `Unicorn.call()`.
3. The attacker includes a malicious Javascript payload as one of the arguments passed to `Unicorn.call()`.
4. The Django Unicorn backend receives the message, processes the `callMethod` action, and invokes the specified component method, passing the attacker-controlled Javascript payload as an argument.
5. The component method logic or the template rendering process incorporates the argument into the HTML output without sufficient HTML encoding.
6. The server sends the re-rendered component HTML back to the client.
7. The browser renders the updated component, and because the malicious Javascript payload was not properly encoded, it is executed by the browser, resulting in XSS.

Impact:
Successful exploitation of this vulnerability allows an attacker to execute arbitrary Javascript code in the victim's browser within the security context of the vulnerable web application. This can lead to:
- Session hijacking: Stealing session cookies, allowing the attacker to impersonate the victim and gain unauthorized access to their account.
- Account takeover: Performing actions on behalf of the victim, including modifying account details, accessing sensitive information, or initiating unauthorized transactions.
- Defacement: Altering the visual appearance or content of the web page as seen by the victim.
- Redirection to malicious sites: Redirecting the victim to attacker-controlled websites, potentially for phishing or malware distribution.
- Information theft: Accessing and exfiltrating sensitive information displayed on the page or making requests to backend services on behalf of the user, potentially leaking confidential data.

Vulnerability rank: High

Currently implemented mitigations:
- HTML encoding for field values: Django Unicorn automatically HTML encodes component field values that are updated through `unicorn:model` directives. This is documented in `docs\source\changelog.md` for version 0.36.0 and `docs\source\views.md`.
- `safe` meta attribute and template filter: Django Unicorn provides mechanisms for developers to bypass HTML encoding for specific component fields using the `safe` meta attribute in the component view or the `safe` template filter in templates, as detailed in `docs\source\views.md`. This is intended for cases where developers explicitly need to render unencoded HTML, but it requires careful usage to avoid introducing XSS vulnerabilities.

Missing mitigations:
- Consistent HTML encoding for `Unicorn.call()` arguments: Arguments passed to component methods via `Unicorn.call()` are not consistently HTML encoded by default when they are rendered in the component template. This creates a potential bypass to the existing XSS mitigations if developers render these arguments directly in templates without manual encoding or using the `safe` filter/attribute incorrectly.

Preconditions:
1. Django Unicorn is used in the web application and components are integrated into web pages.
2. At least one Django Unicorn component has a method that can be invoked from the frontend using `Unicorn.call()`.
3. The component's template renders data that is dynamically influenced by arguments passed to a component method that can be called via `Unicorn.call()`.
4. The component template does not explicitly HTML-encode the arguments received from `Unicorn.call()` when rendering them.

Source code analysis:
1. `django_unicorn\views.py`: The `message` view function is the endpoint for handling Unicorn requests. It processes actions from the request body.
2. `django_unicorn\views\__init__.py`: The `_process_component_request` function handles the lifecycle of a component for each request, including action processing and rendering.
3. `django_unicorn\views\action_parsers\call_method.py`: The `handle` function is responsible for processing `callMethod` actions. It parses the method name and arguments from the payload and calls the corresponding method on the component instance using `_call_method_name`.
4. `django_unicorn\views\action_parsers\call_method.py`: The `_call_method_name` function retrieves the method from the component and calls it with the provided arguments. It casts the arguments to the expected types based on type hints but does not perform HTML encoding on these arguments.
5. `django_unicorn\components\unicorn_view.py`: The `render` method in `UnicornView` uses `UnicornTemplateResponse` to render the component.
6. `django_unicorn\components\unicorn_template_response.py`: The `UnicornTemplateResponse.render` method renders the template and updates the HTML using BeautifulSoup. It uses `sanitize_html` for JSON data within script tags, but not for general template rendering of component data, including method arguments.
7. `django_unicorn\templatetags\unicorn.py`: The `unicorn` template tag is used to render components. It passes the component instance to the template context, allowing template code to access component properties and methods, including arguments potentially passed via `Unicorn.call()`.
8. Vulnerability Point: If a component method is designed to render arguments received from `Unicorn.call()` directly within its template without explicit HTML escaping, and the automatic HTML encoding mechanism primarily focuses on `unicorn:model` updates, then XSS is possible. The arguments passed via `Unicorn.call()` are not automatically and consistently HTML encoded when re-rendered in the template context, especially if developers are not aware of the need for manual escaping using Django's template filters or the `safe` attribute/filter.

Security test case:
1. Create a Django Unicorn component named `call_arg_xss_test`.
2. In `call_arg_xss_test.py`, define a component view `CallArgXssTestView` with a method `receive_and_render(self, arg)`. Inside this method, store the `arg` directly into a component property named `render_arg`:
   ```python
   from django_unicorn.components import UnicornView

   class CallArgXssTestView(UnicornView):
       render_arg = ""

       def receive_and_render(self, arg):
           self.render_arg = arg
   ```
3. In `call_arg_xss_test.html`, render the `render_arg` property within the component template without any HTML escaping filters: `<div>{{ render_arg }}</div>`.
4. Create a Django template that includes the `call_arg_xss_test` component using the `{% unicorn ... %}` tag.
5. Create a Django view that renders the template containing the `call_arg_xss_test` component.
6. Access the Django view in a web browser.
7. Open the browser's developer console.
8. Execute the following Javascript code to call the `receive_and_render` method of the `call_arg_xss_test` component, passing a malicious Javascript payload as the argument:
   ```javascript
   Unicorn.call('call_arg_xss_test', 'receive_and_render', '<img src=x onerror=alert("XSS_via_call_arg")>')
   ```
9. Observe if an alert box with the message "XSS_via_call_arg" appears in the browser. If the alert box appears, it confirms that the Javascript payload was executed, demonstrating the XSS vulnerability.
10. Inspect the HTML source of the re-rendered component in the browser's developer tools to verify if the malicious payload is rendered directly in the HTML without HTML encoding, specifically within the `<div>` element that renders `{{ render_arg }}`.
