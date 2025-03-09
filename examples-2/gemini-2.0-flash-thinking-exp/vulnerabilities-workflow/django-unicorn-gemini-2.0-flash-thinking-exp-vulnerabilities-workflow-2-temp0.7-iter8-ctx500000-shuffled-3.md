### 1. Vulnerability Name: Reflected Cross-Site Scripting (XSS) through Component Property

- Description:
    1. An attacker crafts a malicious URL containing JavaScript code in a component property, e.g., `{% unicorn 'hello-world' name="<script>alert('XSS')</script>" %}`.
    2. The Django template renders the component, including the malicious script in the `name` property.
    3. When the component is initially rendered or updated via AJAX, the malicious script is injected into the DOM because the `{{ name|title }}` template tag in `hello-world.html` does not sanitize the input.
    4. The victim's browser executes the injected JavaScript code, leading to XSS.

- Impact:
    - High. An attacker can execute arbitrary JavaScript code in the victim's browser. This can lead to session hijacking, defacement, redirection to malicious websites, or theft of sensitive information.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - Django automatically escapes HTML content rendered in templates by default. However, in this case, the vulnerability lies in directly rendering component properties without explicit sanitization within the component's template.
    - The documentation mentions that `Unicorn` HTML encodes updated field values to prevent XSS attacks, but this default encoding might not be sufficient in all cases, especially when developers directly render component properties in templates without further sanitization.

- Missing Mitigations:
    - Input sanitization should be explicitly applied to component properties, especially when rendering them in templates.
    - Consider using Django's `escapejs` template filter for properties that might contain JavaScript code or HTML that should be treated as plain text.
    - Documentation should strongly emphasize the importance of sanitizing user inputs and component properties to prevent XSS.

- Preconditions:
    - The attacker needs to be able to influence the component properties, either through URL parameters, form inputs, or other means of data injection that gets passed to the `unicorn` template tag.
    - The component template must render the vulnerable property without sufficient sanitization.

- Source Code Analysis:
    1. **File:** `..\django-unicorn\docs\source\components.md` and `..\django-unicorn\docs\source\templates.md` show examples using `unicorn:model` and rendering component properties like `{{ name|title }}` in `hello-world.html`.
    2. **File:** `..\django-unicorn\example\unicorn\components\hello_world.py` and `..\django-unicorn\example\unicorn\components\hello_world.html` demonstrate a basic component that renders the `name` property without sanitization.
    3. **File:** `..\django-unicorn\templatetags\unicorn.py` and `django_unicorn\components\unicorn_template_response.py` handle the rendering process, but there's no automatic sanitization of component properties before they are passed to the template context or rendered in the HTML.
    4. **File:** `..\django-unicorn\docs\source\views.md` mentions `Meta.safe` to opt-in to allow a field to be returned without encoding, implying that encoding is the default, but doesn't enforce sanitization for initial rendering or component properties in general.

- Security Test Case:
    1. Create a Django project with django-unicorn installed and configured.
    2. Create a component named `xss_test` in a Django app (e.g., `test_app`) with the following files:
        - `test_app/components/xss_test.py`:
          ```python
          from django_unicorn.components import UnicornView

          class XssTestView(UnicornView):
              xss_payload = ""
          ```
        - `test_app/templates/unicorn/xss_test.html`:
          ```html
          <div>
              {{ xss_payload|safe }}
          </div>
          ```
        - `test_app/templates/index.html`:
          ```html
          {% load unicorn %}
          <html>
          <head>
              {% unicorn_scripts %}
          </head>
          <body>
              {% csrf_token %}
              {% unicorn 'xss-test' xss_payload=xss_payload %}
          </body>
          </html>
          ```
        - `test_app/views.py`:
          ```python
          from django.shortcuts import render

          def index(request):
              xss_payload = request.GET.get('xss', '<script>alert("XSS Vulnerability")</script>')
              return render(request, 'index.html', {'xss_payload': xss_payload})
          ```
        - `test_app/urls.py`:
          ```python
          from django.urls import path
          from .views import index

          urlpatterns = [
              path('', index, name='index'),
          ]
          ```
        - `project/urls.py`:
          ```python
          from django.urls import include, path

          urlpatterns = [
              path('', include('test_app.urls')),
              path("unicorn/", include("django_unicorn.urls")),
          ]
          ```
    3. Run the Django development server.
    4. Access the URL `/` with the crafted XSS payload in the query parameter: `http://127.0.0.1:8000/?xss=%3Cscript%3Ealert(%22XSS%20Vulnerability%22)%3C/script%3E`
    5. Observe that an alert box with "XSS Vulnerability" is displayed in the browser, indicating successful XSS exploitation.
