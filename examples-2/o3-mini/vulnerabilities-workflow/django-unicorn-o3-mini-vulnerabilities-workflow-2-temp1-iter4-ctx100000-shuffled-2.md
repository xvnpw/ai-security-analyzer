- **Vulnerability Name:** Cross‑Site Scripting (XSS) via Unsanitized Component Properties
  **Description:**
  The framework automatically serializes every public component property and—unless explicitly marked as “safe”—HTML‑encodes the value before sending it to the browser. However, developers may “opt‑in” to disable encoding by adding property names to a Meta‑configuration (e.g. via the Meta.safe tuple). If an attacker can supply input (typically via a unicorn:model binding in an AJAX request) for one of those “safe” properties, malicious HTML or JavaScript (e.g. `<script>alert('XSS')</script>`) can be injected directly into the rendered page without escaping. The step‑by‑step workflow includes:
  1. A component property is explicitly marked as “safe” via its Meta configuration.
  2. An attacker provides input via an interactive element (for example, a unicorn:model field) that includes malicious payload.
  3. Upon re‑rendering—either initially or via an AJAX update—the unsanitized value is inserted verbatim into the DOM.
  4. The browser interprets and executes the injected payload.
  **Impact:**
  Successful exploitation can lead to arbitrary JavaScript execution in the victim’s browser. This may be used for session hijacking, cookie theft, redirections, and further client–side compromise.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - By default, all component properties are HTML‑encoded before transmission.
  - The framework’s documentation warns developers about the risks of marking properties as safe.
  **Missing Mitigations:**
  - Additional runtime sanitization and/or the use of strict Content Security Policies (CSP) on properties marked safe.
  **Preconditions:**
  - A component developer has opted into disabling HTML encoding for a property (e.g. by listing it in Meta.safe).
  - An attacker is able to supply input to that property via AJAX‑driven interactions.
  **Source Code Analysis:**
  - In the rendering routine (e.g. in `UnicornTemplateResponse.render`), component properties are dumped into the HTML (often into attributes like `unicorn:data`). When a property is marked “safe”, its value bypasses default HTML‑escaping so that any embedded script tags or HTML are rendered as is.
  **Security Test Case:**
  1. Create a custom component with a property (e.g. “something_safe”) and add it to its Meta.safe tuple.
  2. Deploy this component in a test environment and load its page in a browser.
  3. Use developer tools or an intercepting proxy to send an AJAX request to the Unicorn endpoint that sets “something_safe” to a payload such as `<script>document.body.dataset.xss_executed = 'yes';</script>`.
  4. Confirm that after the component re‑renders the injected payload executes (for example, the `data‑xss_executed` attribute appears on the body).
  5. A successful test confirms that unsanitized input is rendered without proper encoding.
