var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function attach( auth, parameters, callback ){
  var possibleHeaders = ['opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/volumeAttachments/',
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
                   { path : auth.RESTversion + '/volumeAttachments/' + encodeURIComponent(parameters.volumeAttachmentId),
                     host : endpoint.service.core[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
};

function list( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['availabilityDomain', 'compartmentId', 'instanceId', 'limit', 'page', 'volumeId'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/volumes' + queryString,
                     host : endpoint.service.core[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
};

module.exports = {
    list: list,
    get: get,
    attach: attach
    };
