# Flask-Specific Threat Model

## 1. Debug Mode Enabled in Production
- **Description**: Attackers can trigger detailed error pages (stack traces) or exploit the Werkzeug debugger console (if PIN is brute-forced/leaked) to execute arbitrary code.
- **Impact**: Information leakage, remote code execution.
- **Flask Component**: `debug=True` flag, Werkzeug debugger.
- **Risk Severity**: Critical
- **Mitigation**: Disable debug mode in production (`debug=False`). Remove/disable Werkzeug debugger in production environments.

## 2. Jinja2 Server-Side Template Injection (SSTI)
- **Description**: Unsafe rendering of user-controlled input in Jinja2 templates allows attackers to inject template code, leading to remote code execution (e.g., via `{{ config.items() }}` or `{{ ''.__class__ }}`).
- **Impact**: Full server compromise.
- **Flask Component**: Jinja2 template engine (`render_template`, `render_template_string`).
- **Risk Severity**: Critical
- **Mitigation**: Never render unvalidated user input as templates. Use Jinja2 sandboxing for dynamic templates.

## 3. Insecure Session Cookie Configuration
- **Description**: Flask signs session cookies by default but does not encrypt them. Attackers with access to the cookie can decode its contents if the `SECRET_KEY` is weak or exposed.
- **Impact**: Session hijacking, privilege escalation.
- **Flask Component**: `flask.session` object, `SECRET_KEY` configuration.
- **Risk Severity**: High
- **Mitigation**: Use a strong `SECRET_KEY`, rotate keys periodically, and set `SESSION_COOKIE_HTTPONLY`/`SESSION_COOKIE_SECURE`.

## 4. Unsafe Redirects via `flask.redirect`
- **Description**: Using unvalidated user input in `flask.redirect()` allows attackers to redirect users to malicious domains (open redirects).
- **Impact**: Phishing, credential theft.
- **Flask Component**: `flask.redirect` function.
- **Risk Severity**: Medium
- **Mitigation**: Validate redirect URLs against an allowlist or use relative paths.

## 5. Missing CSRF Protection by Default
- **Description**: Flask does not include built-in CSRF protection, making applications vulnerable to state-changing request forgery unless explicitly mitigated.
- **Impact**: Unauthorized actions (e.g., password changes, payments).
- **Flask Component**: Core request handling.
- **Risk Severity**: High
- **Mitigation**: Use Flask-WTF or similar extensions to enforce CSRF tokens on POST requests.

## 6. Clickjacking via Missing Security Headers
- **Description**: Flask does not set security headers like `X-Frame-Options` by default, enabling clickjacking attacks.
- **Impact**: UI redress attacks forcing unintended user actions.
- **Flask Component**: Response headers.
- **Risk Severity**: Medium
- **Mitigation**: Use `flask-talisman` or manually set headers like `X-Frame-Options: DENY`.

## 7. Host Header Poisoning
- **Description**: Attackers spoof the `Host` header to bypass authentication, poison caches, or trigger SSRF if the app uses `request.host` unsafely.
- **Impact**: Cache poisoning, SSRF, authentication bypass.
- **Flask Component**: `request.host` attribute.
- **Risk Severity**: High
- **Mitigation**: Configure `SERVER_NAME` and validate `Host` headers via middleware.

## 8. Insecure File Handling with `flask.send_file`
- **Description**: Using unsanitized user input in `flask.send_file()` can lead to directory traversal (e.g., `../../../etc/passwd`).
- **Impact**: Arbitrary file read on the server.
- **Flask Component**: `flask.send_file` function.
- **Risk Severity**: Medium
- **Mitigation**: Validate and sanitize file paths. Use `os.path.abspath` and `os.path.commonprefix` checks.

## 9. Extension-Related Vulnerabilities
- **Description**: Third-party Flask extensions (e.g., Flask-SQLAlchemy, Flask-Admin) may introduce vulnerabilities if outdated or poorly configured.
- **Impact**: Varies (e.g., SQL injection, privilege escalation).
- **Flask Component**: Flask extension ecosystem.
- **Risk Severity**: Medium
- **Mitigation**: Vet extensions for active maintenance, use minimal required permissions, and update regularly.

## 10. Information Leakage via Default Error Pages
- **Description**: Flask’s default error pages disclose framework/version details in production unless overridden.
- **Impact**: Reconnaissance for targeted exploits.
- **Flask Component**: Default error handlers.
- **Risk Severity**: Low
- **Mitigation**: Implement custom error pages using `@app.errorhandler`.
