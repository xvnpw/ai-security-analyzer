## Vulnerability List:

### Vulnerability Name: Server-Side Template Injection via Component Arguments

* Description:
    1. An attacker crafts a malicious component name or component arguments when using the `{% unicorn %}` template tag.
    2. If the component name or arguments are not properly sanitized or validated by `django-unicorn`, it may be possible to inject template code.
    3. This injected template code is then executed on the server when `django-unicorn` renders the component.

* Impact:
    Successful exploitation can lead to Server-Side Template Injection (SSTI). This allows the attacker to execute arbitrary Python code on the server, potentially leading to:
    - Data Breaches: Access to sensitive data, including database credentials, environment variables, and application secrets.
    - Server Takeover: Complete control of the server, allowing the attacker to modify files, install malware, and pivot to internal networks.
    - Denial of Service: Crashing the application or server.

* Vulnerability Rank: Critical

* Currently Implemented Mitigations:
    The project seems to rely on Django's template engine for safety, and does not appear to have specific sanitization for component names or arguments beyond standard Django template processing.  There are no explicit mitigations in the provided code snippets to prevent SSTI when using component names or arguments directly from user input in the `{% unicorn %}` tag.

* Missing Mitigations:
    - Input sanitization and validation for component names and arguments used in the `{% unicorn %}` template tag.
    - Code review to ensure that component loading and rendering logic does not inadvertently introduce SSTI vulnerabilities.
    - Security tests specifically targeting SSTI vulnerabilities in component rendering.

* Preconditions:
    - The application uses `django-unicorn` and allows user-controlled input to dynamically determine the component name or component arguments passed to the `{% unicorn %}` template tag.
    - The attacker needs to be able to influence the data used in the template rendering context that gets passed to the `{% unicorn %}` tag.

* Source Code Analysis:
    1. **templatetags/unicorn.py (and django_unicorn/templatetags/unicorn.py):** The `unicorn` template tag handler in `UnicornNode.render` takes the component name and arguments directly from the template string:
    ```python
    component_name = self.component_name.resolve(context)
    resolved_args = []
    for value in self.args:
        resolved_arg = template.Variable(value).resolve(context)
        resolved_args.append(resolved_arg)
    resolved_kwargs = self.kwargs.copy()
    for key, value in self.unparseable_kwargs.items():
        try:
            resolved_value = template.Variable(value).resolve(context)
            resolved_kwargs.update({key: resolved_value})
        except TypeError:
            resolved_kwargs.update({key: value})
        except template.VariableDoesNotExist:
            if value.endswith(".id"):
                pk_val = value.replace(".id", ".pk")
                try:
                    resolved_kwargs.update({key: template.Variable(pk_val).resolve(context)})
                    except TypeError:
                        resolved_kwargs.update({key: value})
                    except template.VariableDoesNotExist:
                        pass
    ```
    2. The `component_name` and `resolved_kwargs` are directly used to create a `UnicornView` instance via `UnicornView.create`:
    ```python
    self.view = UnicornView.create(
        component_id=component_id,
        component_name=component_name,
        component_key=self.component_key,
        parent=self.parent,
        request=request,
        component_args=resolved_args,
        kwargs=resolved_kwargs,
    )
    ```
    3. The `UnicornView.create` and `UnicornView.render` methods use the resolved component name to dynamically load and render the component. If the `component_name` is constructed using unsanitized user input and not properly validated, it could be manipulated to load and execute arbitrary template code. Similarly, if `resolved_kwargs` contain malicious template code, it could be injected into the component rendering context and executed.

* Security Test Case:
    1. Create a Django view that renders a template and allows user input to influence component arguments. For example, modify `example/www/views.py` to include:
    ```python
    from django.shortcuts import render

    def index(request):
        context = {}
        component_argument = request.GET.get('arg', 'default_value')
        context['component_arg'] = component_argument
        return render(request, "www/index.html", context)
    ```
    2. Modify `example/www/templates/www/index.html` to pass the user-controlled input as a component argument:
    ```html
    {% load unicorn %}
    {% csrf_token %}

    {% unicorn 'hello-world' component_argument=component_arg %}

    {% unicorn_scripts %}
    ```
    3. Access the Django view through a browser and append a malicious payload to the URL as a query parameter. For example: `http://127.0.0.1:8000/?arg=</p><p>Malicious Payload: {{settings.SECRET_KEY}}</p><p>`
    4. Inspect the rendered HTML source code. If the `settings.SECRET_KEY` or other sensitive information is revealed in the HTML output, it confirms the SSTI vulnerability.
    5. As a more advanced test, try to execute arbitrary code by injecting template commands that call Python functions. For example, try to inject `{% system 'ls -al' %}` if `{% load %}`` allows `{% load system from external_library %}`. (Note: Django template engine might block direct execution of shell commands by default, but more sophisticated payloads could potentially bypass these restrictions or exploit other template features to achieve code execution).

This vulnerability allows a malicious actor to leverage the dynamic component rendering functionality to perform SSTI, leading to severe security consequences. It's crucial to implement robust input validation and sanitization to mitigate this risk.


### Vulnerability Name: Insecure Direct Object Reference (IDOR) via Model Type Hinting in Method Arguments

* Description:
    1. When a component method is type-hinted with a Django Model, `django-unicorn` automatically tries to fetch the model instance from the database using the provided argument value as a primary key (or other specified key).
    2. If a component method takes a Django Model as an argument and uses this model instance without proper authorization checks, an attacker could potentially manipulate the method arguments (specifically the primary key value) to access or modify model instances they should not have access to.
    3. This is possible if the component relies solely on type hinting for object retrieval and lacks explicit authorization or permission checks within the method logic.

* Impact:
    - Unauthorized data access: An attacker can access details of database objects by manipulating the primary key value in method arguments.
    - Data manipulation: In more critical scenarios, if the method allows modification of the fetched model instance, an attacker could potentially modify data they are not authorized to change.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    No specific mitigations are implemented in `django-unicorn` to prevent IDOR via model type hinting. The framework relies on the component developer to implement authorization checks within the component methods if needed.

* Missing Mitigations:
    - Documentation highlighting the potential IDOR risk when using Model type hinting in component methods and recommending explicit authorization checks within the component logic.
    - Secure coding guidelines and examples for developers on how to implement authorization checks in component methods that handle Django Model instances fetched via type hinting.
    - Security tests to verify that components using model type hinting are not vulnerable to IDOR.

* Preconditions:
    - The application uses `django-unicorn`.
    - A component method is type-hinted with a Django Model and takes a primary key (or another identifier) as an argument which is derived from user input.
    - The component method uses the fetched model instance without proper authorization checks.
    - The attacker needs to be able to call this method, potentially through a button click or other UI interaction that triggers a method call.

* Source Code Analysis:
    1. **django_unicorn/views/action_parsers/call_method.py** -> `_call_method_name` function:
    ```python
    def _call_method_name(component: UnicornView, method_name: str, args: Tuple[Any], kwargs: Dict[str, Any]) -> Any:
        ...
        for argument in arguments:
            if argument in type_hints:
                type_hint = type_hints[argument]
                ...
                if is_model:
                    DbModel = type_hint  # noqa: N806
                    key = "pk"
                    value = None

                    if not kwargs:
                        value = args[len(parsed_args)]
                        parsed_args.append(DbModel.objects.get(**{key: value}))
                    else:
                        value = kwargs.get("pk")
                        parsed_kwargs[argument] = DbModel.objects.get(**{key: value})
                ...
    ```
    2. The `_call_method_name` function retrieves a Django Model instance directly from the database using `objects.get()` based on user-provided `value` when the method argument is type-hinted with a Model.
    3. This automatic model retrieval happens without any framework-level authorization checks.
    4. If a component method does not implement its own authorization logic after receiving the Model instance, it can lead to IDOR vulnerabilities if an attacker can manipulate the `value` to access objects they are not authorized to.

* Security Test Case:
    1. Create a Django model, e.g., `SecretNote` with fields `id`, `title`, `content`, and `owner` (ForeignKey to User).
    2. Create a Unicorn component, e.g., `NoteComponentView`, with a method `view_note` that takes a `SecretNote` as an argument and displays the note's content. The method should *not* have any authorization checks.
       ```python
       from django_unicorn.components import UnicornView
       from example.coffee.models import SecretNote  # Assuming SecretNote model is defined

       class NoteComponentView(UnicornView):
           note_content = ""

           def view_note(self, note: SecretNote):
               self.note_content = note.content
       ```
    3. Create a template that uses this component and allows calling the `view_note` method with a note ID from user input (e.g., a text field or URL parameter).
       ```html
       {% load unicorn %}
       <form>
           <input type="text" unicorn:model="note_id">
           <button unicorn:click="view_note(note_id)">View Note</button>
       </form>
       <p>{{ note_content }}</p>
       ```
    4. Create two `SecretNote` instances, one owned by the current user and one owned by another user.
    5. Log in as a user who should only have access to their own notes.
    6. In the application, use the component to try to view the note owned by another user by providing the other user's note ID in the input field.
    7. Observe if the component successfully displays the content of the other user's note. If it does, it confirms the IDOR vulnerability because the user was able to access a resource they shouldn't have access to by directly referencing its ID.

This vulnerability highlights the importance of implementing authorization checks within component methods when using Model type hinting, especially when handling sensitive data. Developers should be aware of this potential risk and follow secure coding practices to prevent unauthorized data access or manipulation.
