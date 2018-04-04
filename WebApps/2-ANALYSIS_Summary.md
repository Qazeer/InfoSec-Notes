# Web Application - Analysis Summary

--------------------------------------------------------------------------------

Once the mapping, and some basic functional analysis, of the web
application have been conducted, the next step is to identify as much
vulnerabilities as possible.<br/><br/>
Summary of the vulnerabilities impacting web applications:

| Component                     | Possible vulnerabilities                     |
|-------------------------------|----------------------------------------------|
| HTTP stack                    | Information leakage through HTTP headers or error message<br/> Supports of unnecessary HTTP methods |
| Clear text communications     | Transmission of credentials and sensitive data<br/>Session hijacking |
| SSL/TLS configuration         | Use of an invalid certificate<br/> Supports of insecure encryption protocols or algorithms |
| Third-party components        | Use of unsecure default configuration<br/> CVE & public exploits                        |
| Client-side validation        | Absence of replicated checks server side     |
| Authentication                | Username enumeration<br/> Weak password policy <br/> Absence of brute force protection mechanisms<br/> Desin flaws of auxiliary functionalities |
| Session                       | Predictable tokens<br/> Insecure handling of tokens |
| Access control                | Horizontal partitioning bypass<br/> Vertical privilege escalation |
| Business logic                | Absence of business validation on data input<br/> Business flaw and vulnerability by design<br/> Absence of anti Cross Site Request Forgery token on core business functionality|
| User-supplied data            | Cross-site scripting<br/> SQL injection <br/> LDAP injection <br/> Template injection<br/>OS code injection <br/> |
| XML                           | XML Injection<br/> XML External Entities (XXE) |
| File download                 | Path traversal <br/> Local and remote file inclusion <br/> |
| File upload                   | Shell/reverse shell upload<br/> Malicious file upload |
| Native code interaction       | Buffer overflows                             |
| Dynamic redirects             | Redirection and header injection attacks     |
| Off-site links & API          | Communication of sensible or tracking information <br/> Leak of query string parameters in the Referer header |