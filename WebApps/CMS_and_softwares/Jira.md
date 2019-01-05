# Web applications - Software Jira

### Overview

Jira is a proprietary issue tracking product developed in Java by Atlassian and
initially released in 2002 which allows bug tracking and agile project
management.

According to Atlassian, Jira is used for issue tracking and project management
by over 75,000 customers in 122 countries.

### Login prompt & default credentials

Access the logon prompt at the URL below and try the default SDK credentials
`admin:admin`.

```
<http | https>://<HOST | IP>/login.jsp
```

### Administrator interface to RCE

Upload the `atlassian-webshell-plugin\atlplug.jar` through the admin web
interface:

```
<http | https>://<HOST | IP>/plugins/servlet/upm
```

Then start and access it to execute system command:

```
<http | https>://<HOST | IP>/plugins/servlet/com.jsos.shell/ShellServlet
```
