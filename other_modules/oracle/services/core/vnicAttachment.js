var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function attach( auth, parameters, callback ){
  var possibleHeaders = ['opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/vnicAttachments/',
                     host : endpoint.service.core[auth.region],
                     method : 'POST',
                     headers : headers,
                     body : options }, 
                   callback );
}

function get( auth, parameters, callback ) {
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/vnicAttachments/' + encodeURIComponent(parameters.vnicAttachmentId),
                     host : endpoint.service.core[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
};

function detatch( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/vnicAttachments/' + encodeURIComponent(parameters.vnicAttachmentId),
                     host : endpoint.service.core[auth.region],
                     headers : headers,
                     method : 'DELETE' },
                    callback );
};

function list( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['compartmentId', 'availabilityDomain', 'instanceId', 'limit', 'page', 'vnicId'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/vnicAttachments/' + queryString,
                     host : endpoint.service.core[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
};

module.exports = {
    list: list,
    get: get,
    attach: attach,
    detatch: detatch
    };
