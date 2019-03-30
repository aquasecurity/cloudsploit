# OCI-Rest-APIs-nodejs

Oracle Cloud Infrastructure REST APIs implemented in node.js.  

Most commands take the form of:

## oci.[serviceName].[resourceType].[action]

For example, to list autonomous datawarehouses:

### oci.databases.autonomousDataWarehouses.list( auth, parameters, callback )

Inputs take the following form...

**auth**: JSON object

```javascript
  auth={
    tenancyId : "xxx.aaa.bbb", // Tenancy OCID
    userId : "user.123.456", // user OCID
    keyFingerprint : "a2:f4:45:ca:98"
    RESTversion : '/20160918',
    region : 'us-ashburn-1',
    object_storage_name : 'abcde' // only needed for amazon S3 access
    privateKey : // the text of the PEM key, NOT the name of the file
  };
```

**parameters**:
  JSON object cantaining any of the parameters (header, query or path ) for the REST call.  For a descrioption of the all of the parameters for any REST call, see here:  <https://docs.cloud.oracle.com/iaas/api/#/>

  eg.  a parameter object to change the freeForm tags of autonomousDatabase might look like

```javascript
  var parameters = {
    autonomousDatabaseId : "asd.jsj.0239409324",
    body : { "freeformTags" : {"tag 1": 123456,
                               "tag 2": "yyy",
                               "another tag": "aaa" },
    };
```

and the call to make the change would be

```javascript
oci.databases.autonomousDatabase.update( auth,
                                         parameters,
                                         function(data){
                                             console.log(data);
                                         } );
```

**callback**:
  Node.js standard callback function.

See the test.js and files in the examples directory for other examples of how to setup the auth an how to call/use the API.