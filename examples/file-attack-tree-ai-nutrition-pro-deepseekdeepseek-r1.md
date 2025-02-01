# Threat Modeling Analysis for AI Nutrition-Pro Using Attack Trees

## 1. Understand the Project

### Overview
**AI Nutrition-Pro** is a cloud-based application that provides AI-driven content generation for dietitians via integrations with meal planner applications. Key features include:
- Integration with external meal planner apps via REST APIs
- ChatGPT-3.5 integration for LLM-powered content generation
- Multi-tenant control plane for client/billing management
- Kong API Gateway for authentication and rate limiting

### Key Components
| Component | Technology | Key Responsibility |
|-----------|------------|--------------------|
| API Gateway | Kong | Authentication, rate limiting, input filtering |
| Web Control Plane | Golang + AWS ECS | Client onboarding, billing, configurations |
| Backend API | Golang + AWS ECS | ChatGPT integration & content generation |
| Databases | Amazon RDS (x2) | Stores tenant data and LLM interactions |

### Dependencies
- External meal planner applications
- OpenAI's ChatGPT-3.5 API
- AWS infrastructure (ECS, RDS)

---

## 2. Root Goal of the Attack Tree
**Compromise AI Nutrition-Pro systems by exploiting vulnerabilities in its architecture or implementation**

```
Root Goal: Compromise AI Nutrition-Pro systems
[OR]
+-- 1. Gain unauthorized access to sensitive data
+-- 2. Disrupt service availability
+-- 3. Manipulate AI-generated content
+-- 4. Compromise administrative controls
```

---

## 3. Expanded Attack Tree Visualization

```
Root Goal: Compromise AI Nutrition-Pro systems
[OR]
+-- 1. Gain unauthorized access to sensitive data
    [OR]
    +-- 1.1 Bypass API Gateway security
        [OR]
        +-- 1.1.1 Steal Meal Planner API keys
            [OR]
            +-- 1.1.1.1 Phish administrators (Social Engineering)
            +-- 1.1.1.2 Exploit insecure key storage
        +-- 1.1.2 Bypass rate limiting
    +-- 1.2 Access databases directly
        [OR]
        +-- 1.2.1 Exploit RDS misconfigurations
        +-- 1.2.2 Compromise database credentials
    +-- 1.3 Intercept TLS communications
        [AND]
        +-- 1.3.1 Compromise TLS certificates
        +-- 1.3.2 MITM network traffic

+-- 2. Disrupt service availability
    [OR]
    +-- 2.1 DDoS API Gateway
    +-- 2.2 Exhaust AWS resources
        [OR]
        +-- 2.2.1 Trigger expensive LLM operations
        +-- 2.2.2 Flood control plane database

+-- 3. Manipulate AI-generated content
    [OR]
    +-- 3.1 Poison training data
        [AND]
        +-- 3.1.1 Compromise meal planner app
        +-- 3.1.2 Inject malicious samples
    +-- 3.2 Execute prompt injection attacks
        [AND]
        +-- 3.2.1 Bypass input filtering
        +-- 3.2.2 Craft malicious prompts

+-- 4. Compromise administrative controls
    [OR]
    +-- 4.1 Gain admin console access
        [OR]
        +-- 4.1.1 Brute-force admin credentials
        +-- 4.1.2 Exploit web control plane vulnerabilities
    +-- 4.2 Modify billing configurations
        [AND]
        +-- 4.2.1 Access control plane DB
        +-- 4.2.2 Alter billing records
```

---

## 4. Node Attributes & Prioritization

| Attack Step | Likelihood | Impact | Effort | Skill | Detection Difficulty |
|-------------|------------|--------|--------|-------|----------------------|
| 1.1.1.1 Phish administrators | Medium | Critical | Low | Low | Medium |
| 1.1.2 Bypass rate limiting | High | High | Medium | Medium | Low |
| 1.2.1 RDS misconfigurations | Medium | Critical | High | High | Medium |
| 3.2.2 Craft malicious prompts | High | High | Low | Medium | High |
| 4.1.2 Web control plane vulns | Medium | Critical | Medium | High | Medium |

**High-Risk Paths:**
1. API key compromise via phishing → Data exfiltration
2. Prompt injection attacks → Malicious content generation
3. Web control plane vulnerabilities → Full system compromise

---

## 5. Mitigation Strategies

### Preventive Measures:
1. API Gateway Security
   - Implement API key rotation
   - Add Web Application Firewall (WAF) to Kong
   - Enforce MFA for admin access

2. Data Protection
   - Enable RDS encryption-at-rest
   - Implement field-level encryption for sensitive data

3. LLM Security
   - Add prompt validation layer
   - Implement output content scanning

### Detective Measures:
1. Monitor for anomalous LLM usage patterns
2. Implement database activity monitoring
3. Set up API request anomaly detection

---

## 6. Key Assumptions
1. Meal planner applications are not fully trusted
2. ChatGPT API responses are not validated
3. TLS 1.2+ is properly configured
4. AWS security groups are correctly configured

---

## 7. Recommended Actions
1. Conduct penetration testing focusing on:
   - API key management workflows
   - Web control plane authentication
   - ChatGPT prompt injection scenarios

2. Implement runtime protection for RDS instances

3. Add audit logging for all admin actions in control plane

This attack tree reveals critical risks in API security and LLM integration that require immediate attention to prevent data breaches and service disruptions.
