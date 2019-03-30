var fs = require( 'fs' );
var oci = require( '../oci' );
var readChunk = require('read-chunk');

// build auth object
var auth={
    tenancyId : 'ocid1.tenancy.oc1..aaaaaaaahm47pxqwunxjqel6jhiuyodldss4z2tx4m24cfmyqys3zndfw3ta',
    userId : 'ocid1.user.oc1..aaaaaaaakb5c25jsxn3xx6jdi5gfoqmtlyb6rwfhqmreucv76ubnofnbspna',
    keyFingerprint : 'd0:77:11:66:7b:a8:90:c0:ef:c7:5c:79:9d:c6:f4:24',
    RESTversion : '/20160918',
    //RESTversion : '/20180115',
    //RESTversion: '/20171215',
    region: 'us-ashburn-1',
    privateKeyPath: '/Users/clbeck/.oci/oci_api_key.pem'
};
auth.privateKey = fs.readFileSync(auth.privateKeyPath, 'ascii');

// set up the parameter object
var parameters = {
      //fileName : "/Users/clbeck/Documents/Autonomous Data Warehouse Blog.docx",
      //fileName : "/Users/clbeck/Desktop/phani.txt",
      fileName : "/Users/clbeck/Desktop/94927a.jpg",
      objectName : '94927a.jpg',
      namespaceName : 'oraclecloud987',
      bucketName : 'pebbles',
      uploadId : '',
      body : { object : '94927a.jpg' } 
    };

// create the multi part upload
oci.objectStore.obj.createMultipartUpload( auth, parameters, 
  function(data){
    parameters.uploadId = data.uploadId;
  });
require( 'deasync' ).loopWhile(function(){return parameters.uploadId == '';});

// calculate the number of chunks for the file
var fileSizeInBytes = fs.statSync(parameters.fileName)["size"];
var chunkSize = 2048;  
var chunks = Math.trunc(fileSizeInBytes/chunkSize) + 1;
var parts = 0;

// loop over the file, chunking it and uploading each chunk
for( var i=0; i<chunks; i++ )
{
 parameters.body = readChunk.sync( parameters.fileName, i*chunkSize, chunkSize );
 parameters.uploadPartNum = i+1;
 oci.objectStore.obj.uploadPart( auth, parameters, function(){ parts += 1; });
}
require( 'deasync' ).loopWhile(function(){return parts != chunks;})


// list all the upload parts and build the partsToCommit array
parts = 0;
parameters.body = '';
var partsToCommitBody = {"partsToCommit" : [] };
oci.objectStore.obj.listMultipartUploadParts( auth, parameters, function(data){
  for( var i=0; i<data.length; i++ ){
    partsToCommitBody.partsToCommit.push( {'partNum': data[i].partNumber, 'etag': data[i].etag });
    parts += 1;
  }
});
require( 'deasync' ).loopWhile(function(){return parts != chunks;})

// commit the multi part upload
parameters.body = partsToCommitBody;
oci.objectStore.obj.commitMultipartUpload( auth, parameters, function(){ console.log('success');} );