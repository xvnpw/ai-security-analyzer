- **Vulnerability Name:** Insecure Deserialization via Pickle in Component Caching
  **Description:**
  The framework caches the complete component state—including parent/child hierarchies and extra context—using Python’s pickle module (see functions in `django_unicorn/cacher.py`). If an attacker is able to write to or otherwise manipulate the cache backend (for example, via a mis‑configured or public Redis instance), they can inject a malicious pickle payload. When the application later restores the component state (via `restore_from_cache`), unprotected deserialization could execute arbitrary code.
  **Impact:**
  An attacker who manipulates the cache can achieve remote code execution, resulting in a complete compromise of the host process.
  **Vulnerability Rank:** Critical
  **Currently Implemented Mitigations:**
  - The framework uses Django’s caching backend, which is typically configured to be accessible only in trusted environments.
  - The caching logic is not directly exposed to end users.
  **Missing Mitigations:**
  - No alternative to pickle is provided (such as a safe JSON‑based serializer) even when caching sensitive state.
  - There are no explicit integrity checks (e.g. signing) on the cached data beyond what is provided by the cache’s configuration.
  **Preconditions:**
  - The attacker must be able to modify or inject cache entries (for example, due to a mis‑configured cache backend).
  - The compromised cache entry is later retrieved and deserialized.
  **Source Code Analysis:**
  - In `django_unicorn/cacher.py`, the class `CacheableComponent` calls `pickle.dumps(component)` during component caching.
  - Later, the function `restore_from_cache()` fetches the cached payload and immediately calls `pickle.loads(...)` without extra verification, making the deserialization unsafe if the cache is externally manipulated.
  **Security Test Case:**
  - Configure the application to use a cache backend that is externally writable (or simulate an attacker writing a malicious pickle payload under the key pattern “unicorn:component:<component_id>”).
  - Trigger a re‑render or AJAX update of the component so that it calls `restore_from_cache()`.
  - Observe that execution of the malicious pickle payload (for example, by causing a known side effect such as writing to a file or logging a marker) confirms the vulnerability.

- **Vulnerability Name:** Cross‑Site Scripting (XSS) via Misuse of “Safe” Fields
  **Description:**
  By default, django‑unicorn HTML‑escapes component properties during rendering using its `sanitize_html()` helper. However, developers may “opt‑in” to bypass escaping (by listing property names in the Meta.safe tuple). If a component property that directly or indirectly contains untrusted user input is marked “safe”, an attacker can supply malicious HTML or JavaScript which will be rendered unescaped.
  **Impact:**
  An attacker might execute arbitrary JavaScript in the victim’s browser. This could lead to session hijacking, cookie theft, or UI defacement.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - The framework HTML‑escapes component properties by default.
  - The `sanitize_html()` helper function (and Django’s built‑in escaping mechanisms) is used during rendering.
  **Missing Mitigations:**
  - No automatic verification or warning is issued when a property is marked safe via Meta.safe.
  - There is no built‑in user input content sanitization before a “safe” field is rendered.
  **Preconditions:**
  - A component property is marked as “safe” in the component’s Meta.safe tuple, and it is later set or updated with data controlled by an attacker.
  **Source Code Analysis:**
  - In *django_unicorn/views/unicorn_view.py*, during output rendering, properties appear “safe” if they are included in the Meta.safe tuple.
  - A payload containing malicious HTML (for example, `<script>alert('XSS')</script>`) injected into such a property bypasses the usual HTML‑escaping.
  **Security Test Case:**
  - Create a test component that marks a property (e.g. “message”) as safe in its Meta.safe tuple.
  - Via an AJAX call or form submission, supply a payload like `<script>alert('XSS')</script>`.
  - Load the affected page in a browser and verify that the script is executed.

- **Vulnerability Name:** Component Hijacking via Checksum Bypass
  **Description:**
  To protect component state from tampering, the framework computes an HMAC‑based checksum on the incoming AJAX payload using Django’s SECRET_KEY. If the SECRET_KEY is weak, guessable, or leaked, an attacker can compute a valid checksum for a malicious payload that modifies state or calls sensitive methods.
  **Impact:**
  With the ability to supply a valid checksum, an attacker may update a component’s internal state arbitrarily or invoke sensitive methods remotely, thereby bypassing inherent safeguards.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - The checksum is generated using HMAC‑SHA256 with the Django SECRET_KEY (see `django_unicorn/utils.py → generate_checksum`).
  - The AJAX endpoint checks that the provided checksum matches the computed value.
  **Missing Mitigations:**
  - No secondary, user‑ or session‑based validation exists to defend against tampering should the SECRET_KEY be weak or leaked.
  - A “defense‑in‑depth” mechanism beyond the checksum is absent.
  **Preconditions:**
  - The attacker must know the Django SECRET_KEY (or exploit a weak key).
  - The AJAX endpoint for component updates is accessible and the attacker can manipulate the payload.
  **Source Code Analysis:**
  - In *django_unicorn/utils.py*, the function `generate_checksum()` creates an HMAC‑SHA256 based on the component’s data and settings.SECRET_KEY.
  - In the request validation phase (see *django_unicorn/views/objects.py*), the provided checksum is compared with one computed on the fly.
  - If an attacker can precompute a valid checksum for a crafted payload, they effectively hijack component state.
  **Security Test Case:**
  - In a test environment, set the Django SECRET_KEY to a known, weak value.
  - Craft an AJAX request payload (for example, a “callMethod” action that changes sensitive state) and compute the correct checksum with the known SECRET_KEY.
  - Submit the payload to the AJAX endpoint and verify that the component state changes as dictated by the attacker.

- **Vulnerability Name:** Arbitrary Component Method Invocation
  **Description:**
  The framework supports remote calling of component methods through AJAX “callMethod” actions. Method names and arguments are parsed (via AST parsing in `django_unicorn/call_method_parser.py`) and invoked. Although the framework restricts access to “private” methods (those beginning with underscores), no fine‑grained authorization exists to prevent sensitive public methods from being called.
  **Impact:**
  An attacker could send a crafted AJAX payload to invoke sensitive component methods (e.g. methods that reset state, modify data, or trigger a redirect), thereby altering application behavior or state without authorization.
  **Vulnerability Rank:** Medium–High
  **Currently Implemented Mitigations:**
  - Only “public” methods (those not beginning with an underscore) are callable via AJAX.
  - The framework uses safe parsing (using AST.literal_eval) and validates method calls with a checksum.
  **Missing Mitigations:**
  - There is no per‑user or per‑session authorization check to restrict which methods can be remotely invoked.
  - There is no explicit “whitelist” or rate‑limiting mechanism to prevent abuse.
  **Preconditions:**
  - A component exposes sensitive public methods without additional access control, and
  - An attacker can manipulate the AJAX “callMethod” payload (with a valid checksum, if possible).
  **Source Code Analysis:**
  - In *django_unicorn/views/action_parsers/call_method.py*, the component method name (and arguments) are parsed from the payload with no additional authorization checks beyond the “public” name filtering.
  - Therefore, if a developer inadvertently exposes dangerous methods, an attacker can invoke these methods remotely.
  **Security Test Case:**
  - Create a test component exposing a sensitive method (for example, one that resets critical data).
  - Using tools such as browser developer tools or curl, forge an AJAX “callMethod” request naming the sensitive method (with valid arguments and checksum).
  - Verify that the sensitive method executes and alters the component state in an unauthorized manner.
