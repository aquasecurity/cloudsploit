// Use this script to test your API Credentials befrore you run your scans

var fs        	= require("fs");
var path      	= require("path");
var oci         = require( './oci' );
var util        = require('util');

//
// default callback function
//
var callback = function(data) {
    console.log(util.inspect(data, {showHidden: false, depth: null}));
};

//
// Set up the auth object
//
var auth={
    RESTversion : '/20160918',
    tenancyId : 'ocid1.tenancy.oc1..',
    userId : 'ocid1.user.oc1..',
    keyFingerprint : 'YOURKEYFINGERPRINT',
    region: 'us-ashburn-1'
};
console.log(__dirname);

auth.privateKey = fs.readFileSync(__dirname + '/config/_oracle/keys/YOURKEYNAME.pem', 'ascii');

//
// set up parameters object
//
var parameters = {
  compartmentId : 'ocid1.compartment.oc1..'
};

//
// List VCNs
//
oci.core.vcn.list( auth, parameters, callback );