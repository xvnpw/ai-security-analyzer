### Critical/High Risk Flask-Specific Attack Surfaces

#### 1. **Insecure Route Handlers with Raw Input Usage**
- **Description**: Endpoints directly using unsanitized user input from Flask's request objects.
- **Flask Contribution**: `request.args`, `request.form`, and `request.json` expose raw user input.
- **Example**: `user_input = request.args.get('param')` used in SQL queries without parameterization.
- **Impact**: SQL injection, command injection, or server compromise.
- **Severity**: Critical
- **Mitigation**: Use Flask-SQLAlchemy for parameterized queries, validate inputs with `Flask-WTF`, and sanitize with `bleach`.

#### 2. **Jinja2 Server-Side Template Injection (SSTI)**
- **Description**: Dynamic template rendering with user-controlled content.
- **Flask Contribution**: `render_template_string()` allows unsafe template rendering.
- **Example**: `render_template_string(f"Welcome {user_input}")` where `user_input = {{ config.SECRET_KEY }}`.
- **Impact**: Secret leakage, remote code execution.
- **Severity**: Critical
- **Mitigation**: Avoid `render_template_string`, enforce strict variable escaping, and sandbox Jinja2 environments.

#### 3. **Weak Client-Side Session Management**
- **Description**: Predictable or tamperable session cookies.
- **Flask Contribution**: Flask stores sessions in signed (but not encrypted) client-side cookies by default.
- **Example**: Using a weak `SECRET_KEY` (e.g., `'dev'`) or missing `SESSION_COOKIE_SECURE`.
- **Impact**: Session hijacking, privilege escalation.
- **Severity**: High
- **Mitigation**: Set a strong `SECRET_KEY`, enable `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, and consider server-side sessions with `Flask-Session`.

#### 4. **Authentication Bypass via Flawed Decorators**
- **Description**: Custom route decorators with insufficient authorization checks.
- **Flask Contribution**: Flask’s decorator-based routing enables custom auth logic.
- **Example**: A decorator that checks `if user.is_authenticated` but skips role validation.
- **Impact**: Unauthorized access to admin endpoints.
- **Severity**: High
- **Mitigation**: Use `Flask-Login` for auth workflows and enforce RBAC with `Flask-Principal`.

#### 5. **Insecure File Uploads via `request.files`**
- **Description**: Unsafe handling of uploaded files leading to path traversal or malware execution.
- **Flask Contribution**: `request.files` provides direct access to file streams.
- **Example**: Saving files using `filename = request.files['file'].filename` without sanitization.
- **Impact**: Remote code execution, directory traversal.
- **Severity**: Critical
- **Mitigation**: Use `werkzeug.utils.secure_filename`, restrict file extensions, and store files outside the web root.

#### 6. **Unsafe Deserialization with `pickle`**
- **Description**: Deserializing untrusted data from Flask requests.
- **Flask Contribution**: Developers might use `pickle` for session/cache data.
- **Example**: `user_data = pickle.loads(request.cookies.get('user'))`.
- **Impact**: Remote code execution.
- **Severity**: Critical
- **Mitigation**: Replace `pickle` with JSON serialization and validate data schemas.

#### 7. **Blueprint/Extension Exploitation**
- **Description**: Vulnerabilities in third-party Flask extensions or misconfigured blueprints.
- **Flask Contribution**: Extensions like `Flask-Admin` or `Flask-RESTful` often integrate deeply with the app.
- **Example**: Exposed `Flask-Admin` panel without authentication at `/admin`.
- **Impact**: Full application compromise via admin interfaces.
- **Severity**: Critical
- **Mitigation**: Audit extensions, disable unused components, and enforce strict access controls.
