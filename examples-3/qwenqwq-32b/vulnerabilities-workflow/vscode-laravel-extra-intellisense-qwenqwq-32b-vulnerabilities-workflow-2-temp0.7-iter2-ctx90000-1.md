# Vulnerability List for Laravel Extra Intellisense Extension

## Vulnerability 1: Arbitrary PHP Code Execution via Route Closures
**Description**:
The extension executes PHP code generated to gather route information. When the extension loads routes via `RouteProvider`, it runs Laravel's routing logic. Malicious route closures (e.g., in `routes/web.php`) can trigger arbitrary PHP code execution. Here's how:
1. An attacker crafts a Laravel project with a route containing malicious code in its closure (e.g., `Route::get('/malicious', function () { exec('rm -rf /'); });`).
2. When the user opens the malicious project in VSCode, the extension executes `RouteProvider.loadRoutes()`.
3. `runLaravel` executes the PHP code to fetch routes, which runs the malicious closure.

**Impact**:
An attacker can execute arbitrary PHP commands on the user's machine, leading to remote code execution (RCE), data theft, or system compromise.

**Vulnerability Rank**: Critical
**Current Mitigations**:
- The `phpCommand` configuration allows users to set a Docker command, but this doesn’t prevent malicious code in the project itself.
- The extension provides a security note warning users about executing untrusted code.

**Missing Mitigations**:
- No validation/sandboxing of executed PHP code.
- No restriction on executing user-controlled Laravel project code.

**Preconditions**:
- User opens a malicious Laravel project in VSCode with the extension enabled.
- The malicious project contains a route with a harmful closure.

**Source Code Analysis**:
In `RouteProvider.ts` (`loadRoutes` method):
```typescript
Helpers.runLaravel(`
    echo json_encode(array_map(function ($route) { ... }, app('router')->getRoutes()->getRoutes()));
`, "HTTP Routes")
```
The `getRoutes()->getRoutes()` call evaluates all registered route closures. If a route closure contains malicious code, it executes when the extension runs this command.

**Security Test Case**:
1. Create a malicious Laravel project with a route in `routes/web.php`:
   ```php
   Route::get('/attack', function () {
       exec('echo "ATTACK SUCCESS" > /tmp/vuln.txt');
   });
   ```
2. Configure the extension's `phpCommand` to point to the malicious project's PHP environment.
3. Open the project in VSCode and wait for the extension to load routes.
4. Check `/tmp/vuln.txt` for the attack string.

---

## Vulnerability 2: Execution of Malicious Middleware Code
**Description**:
The extension executes PHP code to fetch middleware information via `MiddlewareProvider`. If the project includes malicious middleware (e.g., in `app/Http/Middleware`), the extension's middleware scanning will run the middleware's `handle()` method. Steps:
1. An attacker creates a middleware class with harmful code (e.g., `phpinfo()` or file deletion).
2. The extension calls `MiddlewareProvider.loadMiddlewares()`, executing the middleware's logic during reflection.

**Impact**:
Arbitrary code execution in the context of the middleware.

**Vulnerability Rank**: Critical
**Current Mitigations**: Same as Vulnerability 1.

**Missing Mitigations**:
- No restriction on executing middleware code during scanning.

**Preconditions**:
- User opens a project with malicious middleware in `app/Http/Middleware`.

**Source Code Analysis**:
In `MiddlewareProvider.ts` (`loadMiddlewares` method):
```typescript
Helpers.runLaravel(`
    $middlewares = array_merge(...);
    ...
`, "Middlewares")
```
The code uses reflection (`ReflectionMethod`) on middleware classes, potentially executing their `handle()` method if it has side effects.

**Security Test Case**:
1. Create a middleware `app/Http/Middleware/AttackMiddleware.php`:
   ```php
   public function handle($request, Closure $next) {
       file_put_contents('/tmp/vuln.txt', 'ATTACK');
       return $next($request);
   }
   ```
2. Add it to `$routeMiddleware` in `app/Http/Kernel.php`.
3. Open the project in VSCode and observe the `vuln.txt` file created.

---

## Vulnerability 3: Exploitation of Blade Directive Definitions
**Description**:
The extension scans Blade directives dynamically. An attacker can define a malicious Blade directive in `app/Providers/BladeDirectiveServiceProvider.php` that executes harmful code when parsed.

**Impact**:
Arbitrary code execution when the Blade provider scans for custom directives.

**Vulnerability Rank**: Critical
**Current Mitigations**: None.

**Missing Mitigations**: No sandboxing for directive scanning.

**Preconditions**:
- User opens a project with a malicious Blade directive provider.

**Source Code Analysis**:
In `BladeProvider.ts` (`loadCustomDirectives` method):
```typescript
Helpers.runLaravel("$out = []; foreach (app(BladeCompiler::class)->getCustomDirectives() ...", "Custom Blade Directives")
```
The code executes Laravel's Blade compiler, which may run attacker-controlled directives during reflection.

**Security Test Case**:
1. Add a directive in `app/Providers/BladeDirectiveServiceProvider.php`:
   ```php
   Blade::directive('attack', function () { exec('echo "ATTACK" > /tmp/vuln.txt'); });
   ```
2. Open the project in VSCode and check for `/tmp/vuln.txt`.

---

## Vulnerability 4: Malicious Model Code Execution
**Description**:
The extension parses Eloquent models via `EloquentProvider`, which executes model code (e.g., `boot()` methods or event listeners). An attacker can embed malicious code in models.

**Impact**:
Arbitrary code execution when models are loaded.

**Vulnerability Rank**: Critical
**Current Mitigations**: None.

**Missing Mitigations**: No restrictions on model code execution during scanning.

**Preconditions**:
- User opens a project with malicious models.

**Source Code Analysis**:
In `EloquentProvider.ts` (`loadModels` method):
```typescript
Helpers.runLaravel(`include_once base_path("$modelPath/$sourceFile"); ...`, "Eloquent Attributes and Relations")
```
The code uses `include_once` to load model files, executing their initialization logic.

**Security Test Case**:
1. Create a model `app/Models/AttackModel.php`:
   ```php
   class AttackModel extends Model {
       public function __construct() { exec('echo "ATTACK" > /tmp/vuln.txt'); }
   }
   ```
2. Load the project in VSCode and verify the attack file exists.
