# Web Application - Attack surface

 Once the application mapping is done, the task of analyzing the application’s
 functionalities can begin.  
 The end goal is to identify the key attack surface the web application
 exposes.

--------------------------------------------------------------------------------

### Core functionalities

Identify the core functionality of the application, what the application was
created for and the actions that each function is designed to perform when used
as intended.  
A deeper understanding of the web application is necessary in order to
conduct a precise vulnerability assessment.


### Core security mechanisms

Identify the core security mechanisms employed by the application and how they
work.  
Key mechanisms to look for:
  - Authentication
  - Session management
  - Access control
  - Support functions such as user registration and account recovery
  -	Peripheral functions such as administrative interface and logging functions

### Supplied input entry points

Data can be supplied through GET & POST parameters as well as HTTP headers and
URL file path in REST style URL.  
The Target Analyzer BurpSuite engagement tool can be used to list the URL of
the web application that take parameters.

```
[Target] Site map -> right click <target> -> [Engagement tools] Analyzer
```
