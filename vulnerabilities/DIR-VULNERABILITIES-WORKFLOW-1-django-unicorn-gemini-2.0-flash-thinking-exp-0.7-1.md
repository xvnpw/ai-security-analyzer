### Vulnerability List

- Vulnerability Name: Insecure Component Loading via `component_name` in URL

- Description:
    - Step 1: An attacker crafts a malicious `component_name` string. This string could be designed to perform path traversal (e.g., `../`, `..\\`), attempt to load components from unexpected locations, or target internal or administrative components.
    - Step 2: The attacker sends a POST request to the `/unicorn/message/<component_name>` endpoint, replacing `<component_name>` with the malicious string crafted in Step 1. The request should also include a valid payload (even if minimal) to trigger the component loading and message handling logic.
    - Step 3: The `django-unicorn` backend, upon receiving the request, uses the provided `component_name` to dynamically determine and load the corresponding component class and template.
    - Step 4: If the `component_name` is not properly validated or sanitized, the system might load an unintended component, potentially exposing internal functionality or data.
    - Step 5: The attacker observes the application's behavior and responses to determine if the malicious component loading was successful and if any unauthorized actions or information disclosure occurred.

- Impact:
    - **Unauthorized Access to Component Functionality:** An attacker can potentially bypass intended access controls and directly interact with components that should not be publicly accessible. This could include components intended for administrative functions or internal system management.
    - **Information Disclosure:** By loading and manipulating unintended components, an attacker could potentially access sensitive data processed or exposed by these components. This might include configuration details, internal application state, or even data intended for other users or roles.
    - **Potential for Privilege Escalation:**  Access to internal or administrative components could grant an attacker elevated privileges within the application, allowing them to perform actions they are not authorized to do under normal circumstances.
    - **Limited Potential for Remote Code Execution (Conditional and Less Likely in Isolation):** While theoretically possible if combined with other vulnerabilities within the loaded components themselves, achieving Remote Code Execution directly through insecure component loading is less likely and would depend on specific flaws in the loaded, unintended components.  This vulnerability primarily focuses on unauthorized access and information disclosure, which are significant security risks in themselves.

- Vulnerability Rank: **High**

- Currently Implemented Mitigations:
    - Based on the provided files, there is no clear indication of specific input validation or sanitization implemented for the `component_name` in the URL within the `urls.py` or other provided code snippets.
    - The regex `[\w/\.-]+` in `django_unicorn\urls.py`  restricts allowed characters in `component_name` but is **insufficient to prevent path traversal attacks**. It allows dots and forward slashes which are key characters in path traversal sequences.
    - Analysis of `django_unicorn\components\unicorn_view.py` reveals the function `UnicornView.create()` which is responsible for component instantiation. This function uses `get_locations(component_name)` to determine possible locations for the component class. However, `get_locations` function, as seen in `django_unicorn\components\unicorn_view.py`, only performs string manipulation and path construction based on `component_name` and configured apps. **It does not include explicit checks to prevent path traversal or verify component existence before loading.**
    - There are no explicit checks within `UnicornView.create()` or `get_locations()` to validate or sanitize the `component_name` against path traversal attacks.

- Missing Mitigations:
    - Input validation and sanitization for the `component_name` extracted from the URL. This should include:
        - **Strict Whitelisting of Allowed Characters:** Restrict `component_name` to only alphanumeric characters, underscores, and hyphens. **Dots and forward slashes should be strictly disallowed** to effectively prevent path traversal.
        - **Path Traversal Prevention:**  Implement server-side checks to explicitly reject any `component_name` containing path traversal sequences like `../` or `..\\`.  Simply relying on regex-based whitelisting is often insufficient, and dedicated path traversal checks are recommended.
        - **Component Existence Verification:** Before attempting to load a component, the system should verify that a component with the given `component_name` actually exists in the expected component directories and is intended to be publicly accessible. This verification should happen *after* resolving the component path based on `component_name` and *before* attempting to import and instantiate the component class. This should involve checking against a predefined list or structure of valid components.

- Preconditions:
    - The application must be built using the `django-unicorn` framework.
    - The application must expose the default `django-unicorn` URL patterns, including the `/unicorn/message/<component_name>` endpoint, publicly.  This is the default setup for `django-unicorn`, making the precondition easily met in many applications using this framework.

- Source Code Analysis:
    - File: `django_unicorn\urls.py`
        ```python
        urlpatterns = (
            re_path(r"message/(?P<component_name>[\w/\.-]+)", views.message, name="message"),
            path("message", views.message, name="message"),  # Only here to build the correct url in scripts.html
        )
        ```
        - The `re_path` in `django_unicorn\urls.py` captures the `component_name` using the regex `[\w/\.-]+`. This regex allows alphanumeric characters, underscores, hyphens, dots, and forward slashes. While it restricts some special characters, it **does not effectively prevent path traversal sequences like `../`**.
        - The captured `component_name` is passed as a parameter to the `views.message` view function.
    - File: `django_unicorn\components\unicorn_view.py`
        ```python
        @lru_cache(maxsize=128, typed=True)
        def get_locations(component_name: str) -> List[Tuple[str, str]]:
            locations = []

            if "." in component_name:
                # Handle component names that specify a folder structure
                component_name = component_name.replace("/", ".")

                # Handle fully-qualified component names (e.g. `project.unicorn.HelloWorldView`)
                class_name = component_name.split(".")[-1:][0]
                module_name = component_name.replace(f".{class_name}", "")
                locations.append((module_name, class_name))
                # ... rest of the code ...


        @staticmethod
        @timed
        def create(
            *,
            component_id: str,
            component_name: str,
            component_key: str = "",
            parent: Optional["UnicornView"] = None,
            request: Optional[HttpRequest] = None,
            use_cache=True,
            component_args: Optional[List] = None,
            kwargs: Optional[Dict[str, Any]] = None,
        ) -> "UnicornView":
            # ...
            locations = []

            if component_name in location_cache:
                locations.append(location_cache[component_name])
            else:
                locations = get_locations(component_name)

            # ... loop through locations and attempt to import and construct component ...
        ```
        - The `get_locations` function in `django_unicorn\components\unicorn_view.py` is responsible for determining potential locations for component classes based on the provided `component_name`.
        - It manipulates the `component_name` string (replacing `/` with `.`) to construct module and class names.
        - It uses `get_setting("APPS", ...)` to get a list of apps to search for components in, appending `.components` and converting the `component_name` to snake case for module names, and pascal case for class names.
        - **Crucially, there are no checks within `get_locations` or `UnicornView.create` to validate that the constructed module and class names, derived from the attacker-controlled `component_name`, are safe and do not lead to path traversal or loading of unintended modules.**
        - The code relies on `importlib.import_module(module_name)` to load the module and `getattr(module, class_name)` to get the component class. If `module_name` is maliciously crafted using path traversal, this could potentially lead to loading arbitrary modules and classes within the application's scope.
        - The fallback location `components.{module_name}` further illustrates that the system relies on conventions and string manipulation without explicit validation, significantly increasing the risk of insecure component loading.
        - The test file `django_unicorn\tests\components\test_get_locations.py` demonstrates how different forms of `component_name` (kebab-case, with slashes, with dots, fully qualified) are processed by `get_locations`, further highlighting the string manipulation involved and the lack of validation.

    - File: `django_unicorn\views.py` (Not provided in PROJECT FILES, **Needs Further Investigation**)
        - **Missing Code Analysis**: The crucial part of the source code analysis is to examine the `views.message` function in `django_unicorn\views.py`. This function is responsible for handling the `/unicorn/message/<component_name>` endpoint and calling `UnicornView.create()`.
        - **To complete the source code analysis, the following needs to be determined by analyzing `django_unicorn\views.py`:**
            - How is the `component_name` parameter received from the URL and passed to `UnicornView.create()`?
            - Is there any validation or sanitization of the `component_name` within `views.message` *before* calling `UnicornView.create()`?
        - **The current PROJECT FILES do not include `django_unicorn\views.py` or any other files that provide new information to update this vulnerability analysis. Therefore, the analysis remains based on the previously provided `urls.py` and `components\unicorn_view.py` files. The provided `test_set_property_from_data.py` and `pyproject.toml` files are not relevant to this specific vulnerability.**

- Security Test Case:
    - Step 1: Deploy a sample Django application that utilizes `django-unicorn` and exposes at least one component. Ensure the `/unicorn/message/<component_name>` endpoint is publicly accessible.
    - Step 2: Identify a component name used in the application, for example, `hello-world`. Verify that sending a POST request to `/unicorn/message/hello-world` with a valid payload results in the expected component behavior.
    - Step 3: Craft a malicious `component_name` to attempt path traversal. Try the following variations:
        - `../hello-world`
        - `..\\hello-world`
        - `.../.../hello-world`
        - Include URL encoded path traversal sequences: `%2e%2e%2fhello-world`
        - If absolute paths are potentially processed, try an absolute path like `/app/components/hello-world` (adjust `/app/components` to a plausible component path within the application).
        - Try to load a component from a different app or a core Django module if possible, e.g., `django.contrib.admin.views.decorators.staff_member_required` (This is just an example, actual exploitable components need to be identified).
    - Step 4: Send POST requests to `/unicorn/message/<malicious_component_name>` for each crafted `component_name` from Step 3, using a minimal valid payload (e.g., `{"data": {}, "checksum": "test", "id": "test", "name": "test"}`).
    - Step 5: Observe the HTTP responses for each request. Check for:
        - HTTP status codes: Look for 200 OK, 404 Not Found, 500 Internal Server Error, or other unexpected status codes. A 200 OK response for a malicious `component_name` would be a strong indicator of potential insecure component loading.
        - Response content: Examine the HTML or JSON response body for any signs of unintended component execution, error messages that reveal internal paths, or any information that suggests a different component than expected was loaded.
    - Step 6: Analyze application logs (Django logs, web server logs) for each request. Look for:
        - Component loading errors or exceptions.
        - File system access attempts outside the expected component directories.
        - Execution of code or access to resources related to components other than the intended ones.
    - Step 7: If a 200 OK response is received for a malicious `component_name` and the response or logs indicate that an unintended component might have been loaded or accessed, the vulnerability is likely confirmed. Further investigation would involve examining the loaded component's functionality to assess the full extent of the security impact.

**Updated Vulnerability List:**

- Vulnerability Name: Insecure Component Loading via `component_name` in URL
- Description:
    - Step 1: An attacker crafts a malicious `component_name` string. This string could be designed to perform path traversal (e.g., `../`, `..\\`), attempt to load components from unexpected locations, or target internal or administrative components.
    - Step 2: The attacker sends a POST request to the `/unicorn/message/<component_name>` endpoint, replacing `<component_name>` with the malicious string crafted in Step 1. The request should also include a valid payload (even if minimal) to trigger the component loading and message handling logic.
    - Step 3: The `django-unicorn` backend, upon receiving the request, uses the provided `component_name` to dynamically determine and load the corresponding component class and template.
    - Step 4: If the `component_name` is not properly validated or sanitized, the system might load an unintended component, potentially exposing internal functionality or data.
    - Step 5: The attacker observes the application's behavior and responses to determine if the malicious component loading was successful and if any unauthorized actions or information disclosure occurred.
- Impact:
    - **Unauthorized Access to Component Functionality:** An attacker can potentially bypass intended access controls and directly interact with components that should not be publicly accessible. This could include components intended for administrative functions or internal system management.
    - **Information Disclosure:** By loading and manipulating unintended components, an attacker could potentially access sensitive data processed or exposed by these components. This might include configuration details, internal application state, or even data intended for other users or roles.
    - **Potential for Privilege Escalation:**  Access to internal or administrative components could grant an attacker elevated privileges within the application, allowing them to perform actions they are not authorized to do under normal circumstances.
    - **Limited Potential for Remote Code Execution (Conditional and Less Likely in Isolation):** While theoretically possible if combined with other vulnerabilities within the loaded components themselves, achieving Remote Code Execution directly through insecure component loading is less likely and would depend on specific flaws in the loaded, unintended components.  This vulnerability primarily focuses on unauthorized access and information disclosure, which are significant security risks in themselves.
- Vulnerability Rank: **High**
- Currently Implemented Mitigations:
    - Based on the provided files, there is no clear indication of specific input validation or sanitization implemented for the `component_name` in the URL within the `urls.py` or other provided code snippets.
    - The regex `[\w/\.-]+` in `django_unicorn\urls.py`  restricts allowed characters in `component_name` but is **insufficient to prevent path traversal attacks**. It allows dots and forward slashes which are key characters in path traversal sequences.
    - Analysis of `django_unicorn\components\unicorn_view.py` reveals the function `UnicornView.create()` which is responsible for component instantiation. This function uses `get_locations(component_name)` to determine possible locations for the component class. However, `get_locations` function, as seen in `django_unicorn\components\unicorn_view.py`, only performs string manipulation and path construction based on `component_name` and configured apps. **It does not include explicit checks to prevent path traversal or verify component existence before loading.**
    - There are no explicit checks within `UnicornView.create()` or `get_locations()` to validate or sanitize the `component_name` against path traversal attacks.
- Missing Mitigations:
    - Input validation and sanitization for the `component_name` extracted from the URL. This should include:
        - **Strict Whitelisting of Allowed Characters:** Restrict `component_name` to only alphanumeric characters, underscores, and hyphens. **Dots and forward slashes should be strictly disallowed** to effectively prevent path traversal.
        - **Path Traversal Prevention:**  Implement server-side checks to explicitly reject any `component_name` containing path traversal sequences like `../` or `..\\`.  Simply relying on regex-based whitelisting is often insufficient, and dedicated path traversal checks are recommended.
        - **Component Existence Verification:** Before attempting to load a component, the system should verify that a component with the given `component_name` actually exists in the expected component directories and is intended to be publicly accessible. This verification should happen *after* resolving the component path based on `component_name` and *before* attempting to import and instantiate the component class. This should involve checking against a predefined list or structure of valid components.
- Preconditions:
    - The application must be built using the `django-unicorn` framework.
    - The application must expose the default `django-unicorn` URL patterns, including the `/unicorn/message/<component_name>` endpoint, publicly.  This is the default setup for `django-unicorn`, making the precondition easily met in many applications using this framework.
- Source Code Analysis:
    - File: `django_unicorn\urls.py`
        ```python
        urlpatterns = (
            re_path(r"message/(?P<component_name>[\w/\.-]+)", views.message, name="message"),
            path("message", views.message, name="message"),  # Only here to build the correct url in scripts.html
        )
        ```
        - The `re_path` in `django_unicorn\urls.py` captures the `component_name` using the regex `[\w/\.-]+`. This regex allows alphanumeric characters, underscores, hyphens, dots, and forward slashes. While it restricts some special characters, it **does not effectively prevent path traversal sequences like `../`**.
        - The captured `component_name` is passed as a parameter to the `views.message` view function.
    - File: `django_unicorn\components\unicorn_view.py`
        ```python
        @lru_cache(maxsize=128, typed=True)
        def get_locations(component_name: str) -> List[Tuple[str, str]]:
            locations = []

            if "." in component_name:
                # Handle component names that specify a folder structure
                component_name = component_name.replace("/", ".")

                # Handle fully-qualified component names (e.g. `project.unicorn.HelloWorldView`)
                class_name = component_name.split(".")[-1:][0]
                module_name = component_name.replace(f".{class_name}", "")
                locations.append((module_name, class_name))
                # ... rest of the code ...


        @staticmethod
        @timed
        def create(
            *,
            component_id: str,
            component_name: str,
            component_key: str = "",
            parent: Optional["UnicornView"] = None,
            request: Optional[HttpRequest] = None,
            use_cache=True,
            component_args: Optional[List] = None,
            kwargs: Optional[Dict[str, Any]] = None,
        ) -> "UnicornView":
            # ...
            locations = []

            if component_name in location_cache:
                locations.append(location_cache[component_name])
            else:
                locations = get_locations(component_name)

            # ... loop through locations and attempt to import and construct component ...
        ```
        - The `get_locations` function in `django_unicorn\components\unicorn_view.py` is responsible for determining potential locations for component classes based on the provided `component_name`.
        - It manipulates the `component_name` string (replacing `/` with `.`) to construct module and class names.
        - It uses `get_setting("APPS", ...)` to get a list of apps to search for components in, appending `.components` and converting the `component_name` to snake case for module names, and pascal case for class names.
        - **Crucially, there are no checks within `get_locations` or `UnicornView.create` to validate that the constructed module and class names, derived from the attacker-controlled `component_name`, are safe and do not lead to path traversal or loading of unintended modules.**
        - The code relies on `importlib.import_module(module_name)` to load the module and `getattr(module, class_name)` to get the component class. If `module_name` is maliciously crafted using path traversal, this could potentially lead to loading arbitrary modules and classes within the application's scope.
        - The fallback location `components.{module_name}` further illustrates that the system relies on conventions and string manipulation without explicit validation, significantly increasing the risk of insecure component loading.
        - The test file `django_unicorn\tests\components\test_get_locations.py` demonstrates how different forms of `component_name` (kebab-case, with slashes, with dots, fully qualified) are processed by `get_locations`, further highlighting the string manipulation involved and the lack of validation.

    - File: `django_unicorn\views.py` (Not provided in PROJECT FILES, **Needs Further Investigation**)
        - **Missing Code Analysis**: The crucial part of the source code analysis is to examine the `views.message` function in `django_unicorn\views.py`. This function is responsible for handling the `/unicorn/message/<component_name>` endpoint and calling `UnicornView.create()`.
        - **To complete the source code analysis, the following needs to be determined by analyzing `django_unicorn\views.py`:**
            - How is the `component_name` parameter received from the URL and passed to `UnicornView.create()`?
            - Is there any validation or sanitization of the `component_name` within `views.message` *before* calling `UnicornView.create()`?
        - **The current PROJECT FILES do not include `django_unicorn\views.py` or any other files that provide new information to update this vulnerability analysis. Therefore, the analysis remains based on the previously provided `urls.py` and `components\unicorn_view.py` files. The provided `test_set_property_from_data.py` and `pyproject.toml` files are not relevant to this specific vulnerability.**

- Security Test Case:
    - Step 1: Deploy a sample Django application that utilizes `django-unicorn` and exposes at least one component. Ensure the `/unicorn/message/<component_name>` endpoint is publicly accessible.
    - Step 2: Identify a component name used in the application, for example, `hello-world`. Verify that sending a POST request to `/unicorn/message/hello-world` with a valid payload results in the expected component behavior.
    - Step 3: Craft a malicious `component_name` to attempt path traversal. Try the following variations:
        - `../hello-world`
        - `..\\hello-world`
        - `.../.../hello-world`
        - Include URL encoded path traversal sequences: `%2e%2e%2fhello-world`
        - If absolute paths are potentially processed, try an absolute path like `/app/components/hello-world` (adjust `/app/components` to a plausible component path within the application).
        - Try to load a component from a different app or a core Django module if possible, e.g., `django.contrib.admin.views.decorators.staff_member_required` (This is just an example, actual exploitable components need to be identified).
    - Step 4: Send POST requests to `/unicorn/message/<malicious_component_name>` for each crafted `component_name` from Step 3, using a minimal valid payload (e.g., `{"data": {}, "checksum": "test", "id": "test", "name": "test"}`).
    - Step 5: Observe the HTTP responses for each request. Check for:
        - HTTP status codes: Look for 200 OK, 404 Not Found, 500 Internal Server Error, or other unexpected status codes. A 200 OK response for a malicious `component_name` would be a strong indicator of potential insecure component loading.
        - Response content: Examine the HTML or JSON response body for any signs of unintended component execution, error messages that reveal internal paths, or any information that suggests a different component than expected was loaded.
    - Step 6: Analyze application logs (Django logs, web server logs) for each request. Look for:
        - Component loading errors or exceptions.
        - File system access attempts outside the expected component directories.
        - Execution of code or access to resources related to components other than the intended ones.
    - Step 7: If a 200 OK response is received for a malicious `component_name` and the response or logs indicate that an unintended component might have been loaded or accessed, the vulnerability is likely confirmed. Further investigation would involve examining the loaded component's functionality to assess the full extent of the security impact.
