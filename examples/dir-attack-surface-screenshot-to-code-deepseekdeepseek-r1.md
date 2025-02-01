# Attack Surface Analysis for `screenshot-to-code`

## Attack Surface Identification

### Digital Assets & Entry Points (Updated)
7. **Eval Endpoints (routes/evals.py)**
   - `/evals` and `/pairwise-evals` endpoints accepting folder paths
   - File system access for HTML evaluation files
   - Image input processing via `image_to_data_url`

8. **Screenshot API (routes/screenshot.py)**
   - `/api/screenshot` endpoint interacting with external service (screenshotone.com)
   - API key handling for third-party service
   - Image data URL conversion

9. **Video Processing Utilities (video/utils.py)**
   - Video frame extraction and temporary file handling
   - Base64 video data processing
   - Claude API integration for video analysis

### Potential Vulnerabilities (Updated)
7. **Directory Traversal Risks**
   - Path injection in eval endpoints through user-controlled folder parameters
   - Lack of path sanitization in `get_evals` and `get_pairwise_evals`

8. **Third-party Service Integration**
   - ScreenshotOne API key exposure in client requests
   - Dependency on external service availability/security

9. **Video Processing Vulnerabilities**
   - Temporary file handling risks in video processing
   - Potential memory exhaustion from large video files
   - Frame extraction without size validation

## Threat Enumeration (STRIDE Model) - Updated

### 2. Tampering (Expanded)
- **Eval Result Manipulation**: Alteration of stored HTML evaluation files
- **Video Payload Injection**: Malicious video metadata affecting processing

### 4. Information Disclosure (Expanded)
- **Path Traversal**: Access to arbitrary files via eval endpoint folder parameters
- **Screenshot API Key Leakage**: Exposure of ScreenshotOne credentials in network traffic

### 5. Denial of Service (Expanded)
- **Video Processing Bombs**: Specially crafted video files causing resource exhaustion
- **Eval System Overload**: Malicious path parameters triggering excessive file operations

## Impact Assessment - Updates

### New Critical Risks
| Threat | CIA Impact | Severity | Likelihood |
|--------|------------|----------|------------|
| Directory Traversal via Eval Endpoints | Confidentiality | High | Medium |
| Third-party Service Compromise | Availability/Integrity | Medium | Low |
| Video Processing Resource Exhaustion | Availability | Medium | Low |

## Threat Ranking - Updated

1. **AI API Key Exposure** (High)
2. **Directory Traversal in Eval Endpoints** (High)
3. **Unrestricted CORS** (Medium)
4. **Third-party Service Dependency** (Medium)
5. **Video Processing DoS** (Medium)

## Mitigation Recommendations - Additions

6. **Path Handling Security**
   - Implement strict path sanitization in eval endpoints (routes/evals.py)
   - Add allowlist validation for acceptable file paths
   - Use relative paths constrained to designated directories

7. **Third-party Service Protection**
   - Proxy ScreenshotOne API calls through backend (routes/screenshot.py)
   - Encrypt API keys in transit and at rest
   - Implement circuit breaker pattern for external service calls

8. **Video Processing Safeguards**
   - Add file size validation in video processing (video/utils.py)
   - Implement resource quotas for video operations
   - Use secure temporary file handling with automatic cleanup

9. **Enhanced Input Validation**
   - Add MIME type verification for video uploads
   - Implement maximum frame extraction limits
   - Add timeout mechanisms for long-running video operations

## QUESTIONS & ASSUMPTIONS - Updated

2. New Questions:
   - Are eval endpoints protected by authentication/authorization?
   - What security audits have been performed on ScreenshotOne API?
   - Is there validation for maximum video upload size?
   - Are temporary video files securely wiped after processing?

3. New Assumptions:
   - Eval functionality is only used by trusted internal users
   - Video processing occurs in isolated environments
   - All third-party API keys are rotated regularly
