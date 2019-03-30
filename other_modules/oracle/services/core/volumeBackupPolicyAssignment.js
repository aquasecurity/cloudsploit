var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ){
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/volumnBackupPolicyAssignments',
                     host : endpoint.service.core[auth.region],
                     method : 'POST',
                     headers : headers,
                     body : options }, 
                   callback );
}

function getAsset( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['assetId', 'limit', 'page'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/volumnBackupPolicyAssignments/' + queryString,
                     host : endpoint.service.core[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
};

function get( auth, parameters, callback ) {
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + 
                            '/volumnBackupPolicyAssignments/' + encodeURIComponent(parameters.policyAssignmentId),
                     host : endpoint.service.core[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
};


function drop( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/volumnBackupPolicyAssignments/' + encodeURIComponent(parameters.policyAssignmentId),
                     host : endpoint.service.core[auth.region],
                     headers : headers,
                     method : 'DELETE' },
                    callback );
};

module.exports = {
    getAsset: getAsset,
    get: get,
    create: create,
    drop: drop
    };
