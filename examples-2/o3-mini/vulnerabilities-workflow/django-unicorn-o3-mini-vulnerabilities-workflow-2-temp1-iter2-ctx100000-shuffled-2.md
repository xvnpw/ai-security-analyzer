- **Vulnerability Name:** Cross‑Site Scripting (XSS) via Misconfiguration Using Meta.safe
  - **Description:**
    While Unicorn HTML‑encodes all output by default, developers can mark specific public attributes as “safe” (via `Meta.safe` or Django’s `|safe` filter). If user‑controlled input is assigned to such an attribute and then marked safe, any malicious HTML or JavaScript (for example, `<script>alert('XSS')</script>`) will be injected into the page without escaping.
    *Step‑by‑step trigger:*
    1. A component is created where an attribute (e.g. “description”) is directly bound to user input and is explicitly marked safe via `Meta.safe`.
    2. An attacker submits a malicious payload containing script tags into that field.
    3. Because the attribute is declared safe, HTML‑escaping is skipped and the payload is inserted verbatim into the DOM.
    4. Upon component re‑rendering, the injected script executes in the browser.
  - **Impact:**
    Successful exploitation leads to XSS, which can allow session hijacking, theft of user credentials, or even further client‑side attacks such as keylogging.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    • All output is HTML‑encoded by default.
    • The opt‑in mechanism (using `Meta.safe`) requires developers to explicitly mark data as safe.
  - **Missing Mitigations:**
    • Additional runtime warnings or static analysis to flag when user‑controlled input is marked safe.
    • Sanitization of the data even when flagged safe (or rejecting input that contains dangerous HTML elements).
  - **Preconditions:**
    • A component exposes a user‑controlled input via an attribute.
    • That attribute is marked safe in the component’s configuration (e.g. in `Meta.safe`).
    • The user submits malicious input that includes HTML/JavaScript.
  - **Source Code Analysis:**
    In _django_unicorn/components/unicorn_view.py_, after gathering public properties the code checks if a field is listed in `Meta.safe` and then applies Django’s `mark_safe()` to its content. Therefore, any dangerous HTML in that field is not escaped.
  - **Security Test Case:**
    1. Create a test component that accepts input into a field (e.g. “description”) and marks it safe via `Meta.safe`.
    2. In a browser, input a payload like `<script>alert('XSS')</script>` into the field.
    3. Trigger an update (for instance, by blurring the input field) so the component re‑renders.
    4. Use the browser’s developer console to verify that the script executes and that the payload is not escaped.
