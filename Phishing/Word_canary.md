# Phishing - Word canary

### Canary image

A canary image is an image in a Word document that will, whenever the document
is opened in Microsoft `Word` or `libreoffice`, trigger a request to a remote
URL.

In a Capture The Flag scenario requiring phishing, a canary image can be used
to determine if the target is making use of Microsoft Word in order to pursue
Word related attacks (such as Macro, etc.).

The process to create a canary image in a Word `.docx` document is as follow:
  - Insert tab -> Quick Part -> Field
  - Categories: "Links and References"
  - IncludePicture -> "File name or URL": `http://<IP>/canary.gif`
