### Vulnerability List

- Vulnerability Name: Partial Update Target Mismatch
- Description:
    1. An attacker can manipulate the `target` value in a `callMethod` action's `partial` attribute.
    2. This manipulated `target` is sent to the server.
    3. On the server-side, the `_process_component_request` function in `django_unicorn\views\__init__.py` uses `BeautifulSoup`'s `find_all()` method to locate DOM elements matching the provided `target` (either by `unicorn:key` or `id`).
    4. Due to using `find_all()` and only taking the first element, if an attacker provides a `target` value that matches multiple elements in the rendered component's DOM, the server might select an unintended element.
    5. Consequently, the partial update could replace a different part of the page than the developer intended.
    6. This can lead to replacing a safe part of the page with content from a sensitive part of the page, resulting in potential information disclosure.
- Impact: Information Disclosure. An attacker can potentially cause the server to replace a designated part of the webpage with content from a different, possibly sensitive, area of the page. This can lead to unintended exposure of information to the user.
- Vulnerability Rank: High
- Currently Implemented Mitigations: None. The code attempts to retrieve the DOM element based on the provided target, but there is no validation to ensure that the targeted element is the one intended for update by the developer.
- Missing Mitigations:
    - Implement server-side validation to verify that the `target` value corresponds to the DOM element that the developer intended to be updated via `unicorn:partial`.
    - Enhance the DOM selection logic to be more precise and prevent attackers from manipulating the `target` to select unintended elements. Consider using more specific selectors or validating the context of the selected element.
- Preconditions:
    - The application utilizes partial updates with the `unicorn:partial` attribute in Django Unicorn components.
    - An attacker can intercept and modify the JSON payload sent to the server when a component action is triggered, specifically manipulating the `target` value within the `partial` attribute of a `callMethod` action.
- Source Code Analysis:
    File: `django_unicorn\views\__init__.py`
    Function: `_process_component_request`

    ```python
    if partial_doms:
        soup = BeautifulSoup(rendered_component, features="html.parser")

        for partial in partials:
            partial_found = False
            only_id = False
            only_key = False

            target = partial.get("target")

            if not target:
                target = partial.get("key")

                if target:
                    only_key = True

            if not target:
                target = partial.get("id")

                if target:
                    only_id = True

            if not target:
                raise AssertionError("Partial target is required")

            if not only_id:
                for element in soup.find_all(): # Vulnerability: find_all() can return multiple elements
                    if "unicorn:key" in element.attrs and element.attrs["unicorn:key"] == target:
                        partial_doms.append({"key": target, "dom": str(element)}) # Only the first element is appended
                        partial_found = True
                        break

            if not partial_found and not only_key:
                for element in soup.find_all(): # Vulnerability: find_all() can return multiple elements
                    if "id" in element.attrs and element.attrs["id"] == target:
                        partial_doms.append({"id": target, "dom": str(element)}) # Only the first element is appended
                        partial_found = True
                        break
    ```
- Security Test Case:
    1. Create a Django Unicorn component named `TargetMismatchComponent`.
    2. In the component's template (`target_mismatch.html`), create two `div` elements:
        - The first `div` should contain sensitive information (e.g., "Sensitive Information") and have `unicorn:key="sensitive-div"`.
        - The second `div` should be intended for partial update and contain safe information (e.g., "Safe Area"). Give this div `id="safe-div"`.
        - Add a button with `unicorn:click` action that triggers a partial update targeting `safe-div`.
    3. In the component's view (`target_mismatch.py`), create an action method that triggers a partial update for the element with `id="safe-div"`.
    4. Render the `TargetMismatchComponent` in a Django template.
    5. Using browser developer tools or a proxy, intercept the JSON payload sent when the button is clicked.
    6. Modify the `partial` attribute in the JSON payload:
        - Change the `target` value from `"safe-div"` to `"sensitive-div"`.
    7. Send the modified JSON payload to the server.
    8. Inspect the response HTML.
    9. Verify if the content of the `div` with `id="safe-div"` in the browser is replaced with the content of the `div` with `unicorn:key="sensitive-div"` ("Sensitive Information"). If it is, the vulnerability is confirmed as the attacker was able to redirect the partial update to an unintended, sensitive part of the DOM.
