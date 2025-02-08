# Threat Modeling Analysis for AI Nutrition-Pro Using Attack Trees

## 1. Understand the Project

### Overview
AI Nutrition-Pro is a SaaS platform that provides AI-powered diet generation capabilities through API integration with ChatGPT-3.5. Key components include:
- **API Gateway (Kong)**: Entry point handling authentication/rate limiting
- **Web Control Plane**: Management interface for tenant/billing configuration
- **API Application**: Core service processing meal planner requests
- **RDS Databases**: Stores tenant data and LLM interaction logs

### Key Attack Surfaces
1. API Gateway authentication mechanisms
2. LLM prompt injection via meal planner inputs
3. Control plane administration interfaces
4. Database connections between components
5. ChatGPT API integration

## 2. Attack Tree Root Goal
**Compromise AI Nutrition-Pro systems by exploiting vulnerabilities in its architecture**

```
Root Goal: Compromise AI Nutrition-Pro systems
[OR]
+-- 1. Bypass API Gateway security controls
    [OR]
    +-- 1.1 Compromise API key authentication
    +-- 1.2 Exploit Kong vulnerabilities
    +-- 1.3 Forge TLS certificates

+-- 2. Exploit API Application vulnerabilities
    [OR]
    +-- 2.1 LLM prompt injection attacks
    +-- 2.2 SQL injection in diet sample processing
    +-- 2.3 RCE via unsafe deserialization

+-- 3. Compromise Web Control Plane
    [OR]
    +-- 3.1 Admin credential theft/phishing
    +-- 3.2 ECS task injection attacks
    +-- 3.3 RDS credential leakage

+-- 4. Attack ChatGPT integration
    [AND]
    +-- 4.1 Intercept API responses
    +-- 4.2 Manipulate training data

+-- 5. Exploit meal planner integrations
    [OR]
    +-- 5.1 MITM attack on meal planner HTTPS
    +-- 5.2 Poison training samples
```

## 3. Threat Analysis Matrix

| Attack Path | Likelihood | Impact | Effort | Skill | Detection Difficulty |
|-------------|------------|--------|--------|-------|----------------------|
| 1.1 API Key Compromise | High | Critical | Low | Low | Medium |
| 2.1 LLM Prompt Injection | Medium | High | Medium | Medium | High |
| 3.2 ECS Task Injection | Low | Critical | High | High | Medium |
| 5.1 HTTPS MITM | Medium | Medium | Medium | Medium | Low |

## 4. High-Risk Paths

1. **API Key Compromise (1.1)**
   *Justification*: API keys are single authentication factor with high privilege. Leakage through client apps or logs would grant full API access.

2. **LLM Prompt Injection (2.1)**
   *Justification*: Malicious prompts could exfiltrate training data or generate harmful content, damaging brand reputation.

## 5. Mitigation Strategies

1. **API Gateway**
   - Implement key rotation + HMAC signing
   - Regular Kong security patching

2. **API Application**
   - LLM output validation/sanitization
   - Parameterized SQL queries

3. **Control Plane**
   - MFA for admin access
   - ECS task IAM hardening

4. **Database**
   - Column-level encryption for PII
   - Query auditing

## 6. Assumptions

1. API keys are stored in client apps without hardware security
2. No WAF in front of API Gateway
3. ChatGPT responses are trusted without validation
4. ECS tasks use default IAM roles

## 7. Recommended Actions

1. Implement secret management for API keys
2. Add LLM output content filtering
3. Conduct ECS task security review
4. Enable RDS query logging

**Summary**: The architecture presents highest risk through API authentication and LLM integration points. Priority should be given to hardening API key security and implementing AI content validation controls.
