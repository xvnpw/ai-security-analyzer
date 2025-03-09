- Vulnerability Name: Reflected Cross-Site Scripting (XSS) (CVE-2021-42053, Fixed in v0.36.0)
- Description:
    1. An attacker crafts a malicious URL containing a payload in a query parameter or path.
    2. A user clicks on the malicious URL, which leads to a page using django-unicorn component.
    3. The django-unicorn component renders a template that includes user-provided data from the URL (e.g., query parameters) without proper sanitization.
    4. The malicious payload is executed in the user's browser as JavaScript, because the response was not HTML encoded.
- Impact:
    - An attacker can execute arbitrary JavaScript code in the victim's browser.
    - This can lead to session hijacking, cookie theft, defacement of the website, or redirection to malicious sites.
    - In the context of django-unicorn, this is likely to occur within dynamically updated component areas, making it harder to immediately detect for users.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - Fixed in version 0.36.0 by implementing HTML encoding for responses. This is mentioned in `docs/source/changelog.md` for version 0.36.0: "Security fix: for CVE-2021-42053 to prevent XSS attacks ... responses will be HTML encoded going forward".
- Missing Mitigations:
    - Prior to version 0.36.0, HTML encoding of responses was not consistently applied, which was the root cause.
    - While HTML encoding is now implemented by default, developers can still bypass it using the `safe` template filter or `Meta.safe` component option. This feature, while sometimes necessary, requires developers to be explicitly aware of XSS risks and handle sanitization themselves when using `safe`. More documentation and warnings around using `safe` might be beneficial to reinforce awareness of the risks and proper usage.
- Preconditions:
    - The django-unicorn project version is prior to 0.36.0.
    - The application using django-unicorn renders user-provided data from URL parameters or other external sources within a django-unicorn component template without proper sanitization.
- Source Code Analysis:
    - **Before v0.36.0 (Vulnerable Code):** (Hypothetical example based on vulnerability description)
        - Assume a component template like this: `<div>{{ request.GET.param }}</div>`
        - If `request.GET.param` contains `<script>alert('XSS')</script>`, it would be rendered directly into the HTML without encoding.
    - **After v0.36.0 (Mitigated Code):**
        - The response rendering logic was changed to automatically HTML encode all output by default.
        - To render content without encoding, developers must now explicitly use the `safe` filter or `Meta.safe` option.
        - This change ensures that by default, any user-provided data rendered by django-unicorn will be safe from XSS.
- Security Test Case:
    1. **Setup:**
        - Use a django-unicorn project version prior to 0.36.0.
        - Create a django-unicorn component that renders a URL parameter directly in the template, for example, using `{{ request.GET.xss }}`.
        - Include this component in a Django view and template.
    2. **Attack:**
        - Craft a URL to the Django view with the component, appending a query parameter `?xss=<script>alert('XSS')</script>`.
        - Open the crafted URL in a browser.
    3. **Verification (Vulnerable):**
        - An alert box with "XSS" will pop up, demonstrating that the JavaScript code from the URL parameter was executed.
    4. **Mitigation Test (Fixed in v0.36.0+):**
        - Upgrade django-unicorn to version 0.36.0 or later.
        - Repeat steps 1-2.
    5. **Verification (Mitigated):**
        - The alert box will not pop up. Instead, the browser will render the raw string `<script>alert('XSS')</script>` as text, showing that HTML encoding is in place and the XSS vulnerability is mitigated.
