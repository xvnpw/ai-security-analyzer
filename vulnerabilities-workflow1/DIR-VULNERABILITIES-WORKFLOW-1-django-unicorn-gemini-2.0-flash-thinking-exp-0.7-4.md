### Vulnerability List:

* Vulnerability Name: **Insecure Deserialization in Component Caching**
* Description:
    1. An attacker can craft a malicious payload and inject it into the cached component state.
    2. When the cached component is restored from the cache, the malicious payload is deserialized using `pickle.loads` and executed, potentially leading to Remote Code Execution (RCE).
    3. This can happen if the cache backend is compromised or if there is another vulnerability that allows an attacker to modify the cache.
* Impact:
    * Critical. Remote Code Execution (RCE). An attacker can gain full control of the server by executing arbitrary code.
* Vulnerability Rank: **Critical**
* Currently Implemented Mitigations:
    * None in the provided code.
* Missing Mitigations:
    * Implement secure serialization and deserialization practices. Use a safe serialization format like JSON or `orjson` and ensure that deserialization does not lead to code execution. Consider using cryptographic signing or encryption for cached data to prevent tampering. The `pyproject.toml` file includes `orjson` as a dependency, which is a good alternative to `pickle`, but it's not yet implemented in the caching mechanism.
    * Input validation and sanitization on data being cached and restored. Although input validation might not be effective against deserialization attacks, it can add an extra layer of defense.
* Preconditions:
    * Caching is enabled (`UNICORN['SERIAL']['ENABLED'] = True`).
    * A cache backend other than `DummyCache` is configured.
    * An attacker has a way to inject malicious data into the cache backend or compromise the cache backend itself. For example, if the application uses a shared cache like Redis without authentication and proper network segmentation, or if there is another vulnerability that allows cache manipulation.
* Source Code Analysis:
    * File: `django_unicorn/cacher.py`
    * The `cache_full_tree` function iterates through the component tree and caches each component using `cache.set` after serializing it with `pickle.dumps`.
    * File: `django_unicorn/components/unicorn_view.py`
    * The `restore_from_cache` function retrieves cached component data using `cache.get` and deserializes it implicitly when the `cached_component` is used.
    * Pickle is inherently insecure when used to deserialize untrusted data because it can execute arbitrary code during deserialization. If an attacker can replace the serialized component data in the cache with a malicious pickle payload, they can achieve RCE when the component is restored from the cache.
    ```python
    # django_unicorn/cacher.py
    def cache_full_tree(component: "django_unicorn.views.UnicornView"):
        ...
        with CacheableComponent(root) as caching:
            for _component in caching.components():
                cache.set(_component.component_cache_key, _component) # Insecure serialization with pickle.dumps inside cache.set

    def restore_from_cache(
            component_cache_key: str,
            request: Optional[HttpRequest] = None
        ) -> "django_unicorn.views.UnicornView":
        ...
        cached_component = cache.get(component_cache_key) # Retrieve potentially malicious pickled data

        if cached_component:
            ...
            root: django_unicorn.views.UnicornView = cached_component # Insecure deserialization happens implicitly when cached_component is used.
            ...
    ```
* Security Test Case:
    1. Setup:
        * Enable component caching in `settings.py`: `UNICORN = {'SERIAL': {'ENABLED': True}}`
        * Configure a cache backend like `LocMemCache` or `RedisCache`.
        * Create a simple Unicorn component and include it in a Django view.
    2. Vulnerability Injection:
        * Manually craft a malicious pickle payload using `pickle.dumps`. This payload should contain a class that executes arbitrary code upon deserialization (e.g., using `__reduce__` method). The payload should represent a serialized `UnicornView` object or a part of it.
        * Identify the cache key used by `django-unicorn` for the component you created (you can find it in the `cache_full_tree` function or by debugging).
        * Inject this malicious pickle payload directly into the cache backend using the identified cache key. For `LocMemCache`, you might need to access the internal cache dictionary (not recommended for production testing). For Redis, you can use `redis-cli` to set the key with the malicious payload.
    3. Trigger Deserialization:
        * Access the Django view that includes the Unicorn component in a browser. This will trigger the `restore_from_cache` function, which will retrieve and deserialize the malicious pickle payload from the cache.
    4. Verify RCE:
        * Observe if the arbitrary code injected in the pickle payload is executed on the server. For example, the test payload could create a file in the `/tmp` directory, execute `whoami`, or establish a reverse shell connection back to the attacker.

* Vulnerability Name: **Insecure Deserialization in `reset` method**
* Description:
    1. The `reset` method in `UnicornView` deserializes attributes stored in `_resettable_attributes_cache` using `pickle.loads`.
    2. If an attacker can control or modify the pickled data in `_resettable_attributes_cache`, they can inject a malicious payload.
    3. Upon calling the `reset` method, the malicious payload will be deserialized and executed, potentially leading to Remote Code Execution (RCE).
    4. This attack vector is different from the component caching vulnerability and is triggered when the `reset` method is called, which can be invoked by a client-side action.
* Impact:
    * High. Remote Code Execution (RCE). An attacker can potentially execute arbitrary code on the server.
* Vulnerability Rank: **High**
* Currently Implemented Mitigations:
    * None in the provided code.
* Missing Mitigations:
    * Avoid using `pickle.dumps` and `pickle.loads` for serialization and deserialization, especially for data that might be influenced by users or stored in potentially insecure locations.
    * If serialization is necessary for resettable attributes, use a safer serialization format like JSON or `orjson`. The `pyproject.toml` file includes `orjson` as a dependency, which is a good alternative to `pickle`, but it's not yet implemented in the `reset` method.
    * Implement integrity checks, such as cryptographic signing, for the serialized data to ensure it has not been tampered with.
* Preconditions:
    * The application uses components with resettable attributes (i.e., attributes that are instances of `UnicornField` or Django Models without a primary key).
    * An attacker can find a way to modify the pickled data in `_resettable_attributes_cache`. While direct modification of `_resettable_attributes_cache` might not be directly possible for an external attacker, other vulnerabilities or misconfigurations could potentially lead to its compromise. For example, if the component's state, including `_resettable_attributes_cache`, is somehow exposed or can be indirectly manipulated.
    * The `reset` method is called, which can be triggered by a client-side action (e.g., calling a method that internally calls `reset` or if there is a built-in mechanism to trigger reset via user interaction).
* Source Code Analysis:
    * File: `django_unicorn/components/unicorn_view.py`
    * The `_set_resettable_attributes_cache` method pickles the values of attributes that are instances of `UnicornField` or Django Models without a primary key using `pickle.dumps` and stores them in `_resettable_attributes_cache`.
    * The `reset` method iterates through `_resettable_attributes_cache` and deserializes each pickled value using `pickle.loads` to reset the corresponding attribute.
    ```python
    # django_unicorn/components/unicorn_view.py
    class UnicornView(TemplateView):
        ...
        @timed
        def reset(self):
            for (
                attribute_name,
                pickled_value,
            ) in self._resettable_attributes_cache.items():
                try:
                    attribute_value = pickle.loads(pickled_value)  # Insecure deserialization with pickle.loads
                    self._set_property(attribute_name, attribute_value)
                except TypeError:
                    logger.warn(f"Resetting '{attribute_name}' attribute failed because it could not be constructed.")
                    pass
                except pickle.PickleError:
                    logger.warn(f"Resetting '{attribute_name}' attribute failed because it could not be de-pickled.")
                    pass

        @timed
        def _set_resettable_attributes_cache(self) -> None:
            """
            Caches the attributes that are "resettable" in `_resettable_attributes_cache`.
            Cache is a dictionary with key: attribute name; value: pickled attribute value
            """
            self._resettable_attributes_cache = {}

            for attribute_name, attribute_value in self._attributes().items():
                if isinstance(attribute_value, UnicornField):
                    self._resettable_attributes_cache[attribute_name] = pickle.dumps(attribute_value) # Insecure serialization with pickle.dumps
                elif isinstance(attribute_value, Model):
                    if not attribute_value.pk:
                        if attribute_name not in self._resettable_attributes_cache:
                            try:
                                self._resettable_attributes_cache[attribute_name] = pickle.dumps(attribute_value) # Insecure serialization with pickle.dumps
                            except pickle.PickleError:
                                logger.warn(f"Caching '{attribute_name}' failed because it could not be pickled.")
                                pass

    ```
* Security Test Case:
    1. Setup:
        * Create a Unicorn component with a resettable attribute (e.g., an attribute of type `UnicornField`).
        * Implement a method in the component that triggers the `reset` method, or find an existing way to trigger `reset` from the client-side (if available in the application logic).
    2. Vulnerability Injection:
        * In the `_set_resettable_attributes_cache` method (for testing purposes only, in a development environment), or by finding another way to manipulate `_resettable_attributes_cache` (more complex real-world scenario), replace the pickled value for the resettable attribute with a malicious pickle payload. This payload should execute arbitrary code upon deserialization via `pickle.loads`.
    3. Trigger Deserialization:
        * Trigger the `reset` method through the component's method or any available client-side mechanism. This will cause the malicious pickle payload to be deserialized by `pickle.loads` in the `reset` method.
    4. Verify RCE:
        * Observe if the arbitrary code injected in the pickle payload is executed on the server. Verify RCE as described in the "Insecure Deserialization in Component Caching" test case.

* Vulnerability Name: **Potential Command Injection via `startunicorn` management command**
* Description:
    1. The `startunicorn` management command takes user-provided input for the app name and component names as command-line arguments.
    2. The command uses `call_command("startapp", app_name, ...)` to create a Django app if it doesn't exist and also creates directories and files based on the provided component names.
    3. If these inputs are not properly sanitized before being used in `call_command` or when constructing file paths, it could potentially lead to command injection or path traversal vulnerabilities.
* Impact:
    * Medium. Command Injection and/or Path Traversal. An attacker with access to Django management commands could potentially execute arbitrary commands on the server or create/overwrite files in unexpected locations. While direct external exploitation is unlikely, an attacker who gains access to the server (e.g., via compromised admin account or other vulnerabilities) could leverage this.
* Vulnerability Rank: **Medium**
* Currently Implemented Mitigations:
    * None in the provided code.
* Missing Mitigations:
    * Input validation and sanitization for `app_name` and `component_names` in the `startunicorn` management command.
    * For `app_name` used in `call_command("startapp", app_name, ...)`, ensure it only contains alphanumeric characters, underscores, and hyphens and starts with a letter.
    * When creating directories and files based on `component_names`, sanitize the names to prevent path traversal. Use `os.path.join` correctly to avoid issues. Validate that the resulting paths are within the intended directories.
    * Avoid using shell commands or string interpolation to construct commands or file paths. Use safer alternatives like `os.makedirs(path, exist_ok=True)` and `Pathlib` for path manipulation.
* Preconditions:
    * An attacker has access to Django management commands. This is typically not directly accessible to external users but could be exploited by an attacker who has gained some level of access to the server or administrative interface.
* Source Code Analysis:
    * File: `django_unicorn/management/commands/startunicorn.py`
    * The `handle` method takes `app_name` and `component_names` from command-line arguments.
    * It uses `call_command("startapp", app_name, ...)` which might be vulnerable if `app_name` is not sanitized, although `django-admin startapp` itself has some built-in sanitization, it's still best practice to sanitize input.
    * The code constructs file paths using `/` for directory joining and string formatting, which, if `nested_path` or `component_name` are maliciously crafted, could lead to path traversal.
    ```python
    # django_unicorn/management/commands/startunicorn.py
    class Command(BaseCommand):
        ...
        def handle(self, **options):
            ...
            app_name = options["app_name"]
            ...
            if should_create_app.strip().lower() in ("y", "yes"):
                call_command(
                    "startapp",
                    app_name, # Potential command injection if app_name is malicious
                    verbosity=0,
                )
                ...
        ...
        def create_nested_directories(self, paths: Dict[str, Path], nested_path: str) -> None:
            ...
            nested_paths = nested_path.split("/")

            component_path = paths["components"]
            template_path = paths["templates"]

            for _nested_path in nested_paths:
                component_path /= _nested_path # Path traversal if nested_path is malicious
                template_path /= _nested_path # Path traversal if nested_path is malicious
                ...
        ...

        def create_component_and_template(self, paths: Dict[str, Path], nested_path: str, component_name: str) -> None:
            ...
            snake_case_component_name = convert_to_snake_case(component_name)

            component_path = paths["components"] / nested_path / f"{snake_case_component_name}.py" # Path traversal if nested_path or snake_case_component_name is malicious
            ...
            template_path = paths["templates"] / nested_path / f"{component_name}.html" # Path traversal if nested_path or component_name is malicious
            ...
    ```
* Security Test Case:
    1. Setup:
        * Install django-unicorn in a test Django project.
    2. Path Traversal Test:
        * Run the `startunicorn` management command with a malicious component name designed to cause path traversal, e.g., `python manage.py startunicorn myapp "../../../pwned-component"`.
        * Check if files are created outside the intended `components` and `templates` directories, e.g., in the root directory or other sensitive locations.
    3. Command Injection Test (related to `startapp`):
        * Run the `startunicorn` management command with a malicious app name designed to inject shell commands. This is harder to exploit directly through `startapp` but test with a crafted app name, e.g., `python manage.py startunicorn "myapp; touch /tmp/pwned" hello-world`.
        * After running the command, check if unexpected files or directories are created or if commands are executed. In this example, check if the `/tmp/pwned` file is created.
        * Note: The `startapp` command itself has some built-in checks, so direct command injection might be limited, but path traversal and unexpected file creation/overwriting are more likely vulnerabilities.

* Vulnerability Name: **Cross-Site Scripting (XSS) due to unsafe HTML updates (Likely Mitigated, Needs Verification)**
* Description:
    1. If the application dynamically updates HTML content without proper encoding, it might be vulnerable to XSS.
    2. An attacker could inject malicious JavaScript code into data that is rendered by a Unicorn component.
    3. If this data is not properly sanitized when the component updates the DOM, the malicious script could be executed in the user's browser.
* Impact:
    * Medium. Cross-Site Scripting (XSS). An attacker could execute arbitrary JavaScript code in the user's browser, potentially leading to session hijacking, defacement, or other malicious actions.
* Vulnerability Rank: **Medium (Needs Verification)**
* Currently Implemented Mitigations:
    * File: `django_unicorn\docs\source\changelog.md` and `django_unicorn\utils.py`
    * Changelog v0.36.0 mentions "Security fix: for CVE-2021-42053 to prevent XSS attacks ... responses will be HTML encoded going forward".
    * `utils.py` contains `sanitize_html` function which uses `_json_script_escapes` and `mark_safe` to escape HTML.
    * File: `django_unicorn\components\unicorn_template_response.py`
    * `UnicornTemplateResponse.render` method calls `sanitize_html(init)` when creating the init script tag. This suggests that the component initialization data is HTML-encoded.
    * File: `django_unicorn\tests\views\test_process_component_request.py`
    * Tests like `test_html_entities_encoded` confirm that by default, HTML entities are encoded in component responses.
* Missing Mitigations:
    * While HTML encoding is applied to the component initialization script and confirmed in tests for default scenarios, it's crucial to verify that *all* dynamically updated content, especially user-controlled data rendered in component templates and updated via AJAX, is consistently HTML-encoded.
    * Content Security Policy (CSP) headers to further mitigate XSS risks by restricting the sources from which the browser is permitted to load resources.
    * Audit templates to ensure no `{% safe %}` or `|safe` template filters are used to bypass encoding on user-provided data without careful review.
* Preconditions:
    * The application dynamically renders user-controlled data without proper HTML encoding in scenarios *beyond* component initialization scripts, or if `|safe` or `{% safe %}` template filters are used incorrectly.
* Source Code Analysis:
    * File: `django_unicorn\views\__init__.py`
    * The `_process_component_request` function, which handles AJAX requests, marks fields in `component.Meta.safe` as safe using `mark_safe` *after* component processing but *before* rendering. This indicates a default-safe approach, where content is treated as unsafe unless explicitly marked as safe.
    * The `sanitize_html` function in `utils.py` is used for encoding, but proper usage throughout the codebase and in templates needs to be ensured.
* Security Test Case:
    1. Setup:
        * Create a Unicorn component that renders user-controlled data (e.g., from a component property updated via `syncInput` action).
    2. Malicious Input:
        * Inject a malicious XSS payload into the user-controlled data via a form input or other means that triggers a `syncInput` action, e.g., `<img src=x onerror=alert('XSS')>`.
    3. Trigger Component Update:
        * Trigger an action that causes the component to re-render and display the user-controlled data with the XSS payload. This would typically be done by interacting with the UI element bound to the user-controlled data.
    4. Verify XSS Mitigation:
        * Check if the XSS payload is executed in the browser (e.g., if the `alert('XSS')` box appears). If it is not executed and the payload is rendered as text (e.g., `&lt;img src=x onerror=alert('XSS')&gt;`), then HTML encoding is working. If the `alert` box appears, then XSS vulnerability exists.
        * Specifically, test scenarios where data is dynamically updated via AJAX requests and rendered in the component's template to ensure consistent HTML encoding in these cases, and audit templates for misuse of `|safe` and `{% safe %}` filters on user-provided data.

**Note:** The Vulnerability Rank for "Cross-Site Scripting (XSS) due to unsafe HTML updates" is marked as "Medium (Needs Verification)".  This is because while mitigations seem to be in place based on code analysis and changelog, it's crucial to perform the security test case to confirm that XSS is indeed effectively mitigated in all relevant scenarios, especially for dynamically updated content. If verification confirms effective mitigation, the rank could be downgraded to **Low** or even **Informational** depending on the confidence in the mitigation and the remaining theoretical risk.
