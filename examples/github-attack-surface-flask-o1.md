### Debug Mode in Production (Critical)
- **Description**
  Running the application with Flask’s debug mode enabled in production provides an interactive debugger and exposes sensitive information, allowing attackers to execute arbitrary code on the server.

- **How Flask Contributes**
  Flask’s built-in debugger is intended for development. If it remains active in production, the debug console and traceback details become an avenue for exploitation.

- **Example**
  A production error triggers the interactive console instead of serving a generic error page. An attacker can run arbitrary Python commands directly on the server.

- **Impact**
  Full server compromise, data exfiltration, or unauthorized modifications.

- **Risk Severity**
  Critical

- **Mitigation**
  Disable debug mode in production. Set environment variables or configuration files to ensure “FLASK_ENV=production” and “DEBUG=False.” Never deploy your application with “debug=True.”

---

### Hard-Coded Secret Keys (High)
- **Description**
  Including the Flask secret key in source code or repositories allows attackers to craft or forge signed session data, bypassing authentication or impersonating other users.

- **How Flask Contributes**
  Flask uses a secret key to sign and validate session cookies. If the key is stored in plaintext or leaked, session hijacking becomes trivial.

- **Example**
  The application’s GitHub repo includes “SECRET_KEY = 'hardcoded_key_example'” in a config file, enabling anyone with access to craft valid session tokens.

- **Impact**
  Unauthorized session access, account takeovers, and potential privilege escalation.

- **Risk Severity**
  High

- **Mitigation**
  Store Flask’s secret key securely (e.g., environment variables, secrets manager). Rotate keys periodically and avoid committing them to version control.

---

### Missing or Weak CSRF Protections (High)
- **Description**
  State-changing actions are accessible without robust Cross-Site Request Forgery (CSRF) defenses, allowing attackers to exploit authenticated sessions invisibly.

- **How Flask Contributes**
  Flask does not provide built-in CSRF protection by default. Developers must explicitly incorporate a CSRF extension (e.g., Flask-WTF) or manually implement token-based defenses.

- **Example**
  A user’s browser is logged in, and a malicious site hosts a hidden form submitting requests to the vulnerable Flask app, causing unintended actions under the user’s credentials.

- **Impact**
  Unauthorized data changes, resource creation or deletion, and potential privilege escalation.

- **Risk Severity**
  High

- **Mitigation**
  Use a CSRF protection library such as Flask-WTF. Ensure all forms and state-altering endpoints validate unique CSRF tokens, and regenerate tokens periodically or upon session renewal.

---

### Server-Side Template Injection (Critical)
- **Description**
  Improper handling of user-supplied data in Jinja2 templates can lead to remote code execution if the template engine evaluates malicious expressions.

- **How Flask Contributes**
  Flask typically uses Jinja2, which allows powerful template constructs. Rendering user inputs unsafely (e.g., “{{ user_input }}”) can execute arbitrary code on the server.

- **Example**
  An attacker crafts a payload like “{{ config.__class__.__init__.__globals__['os'].system('ls') }}” that executes commands when injected into a template.

- **Impact**
  Full compromise of the application and underlying system, leading to data theft, service disruption, or privilege escalation.

- **Risk Severity**
  Critical

- **Mitigation**
  Avoid rendering raw user inputs in templates. Sanitize or strictly whitelist variables before passing them to Jinja2. Use Jinja2’s escape filters and disable auto-escaping bypass for untrusted data.
