var fs = require( 'fs' );
var oci = require( '../oci' );

//
// default callback function
//
var auth={
  tenancyId : 'ocid1.tenancy.oc1..aaaaaaaag2lewgpfx45exrgreh6ggn6yy5u3ceux6znsdiepplndtmmqonnq',
  userId : 'ocid1.user.oc1..aaaaaaaayzac5nk42n7klwgzzzatyy2vm45v7zc2l4vzwucjmoiymjtpvhka',
  keyFingerprint : 'd0:77:11:66:7b:a8:90:c0:ef:c7:5c:79:9d:c6:f4:24',
  RESTversion : '/20160918',
  region: 'us-ashburn-1'
};
auth.privateKey = fs.readFileSync('/Users/clbeck/.oci/oci_api_key.pem', 'ascii');

// set up parameters
parameters = {
  namespaceName:'gse00014467',
  bucketName:'chris_bucket',
  objectName: 'scrown.jpg'
}

// callback response will be a buffer that you can write to a local file
oci.objectStore.obj.get( auth, parameters, function(resp){
  var buf = Buffer.from(resp, 'utf8');
  fs.writeFile('/Users/clbeck/Desktop/file.jpg', buf, 'binary' , function() {} );
});