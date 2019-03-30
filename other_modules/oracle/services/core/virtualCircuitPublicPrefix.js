var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function bulkAdd( auth, parameters, callback ){
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/virtualCircuits' + encodeURIComponent(parameters.virtualCircuitId) +
                            '/actions/bulkAddPublicPrefixes',
                     host : endpoint.service.core[auth.region],
                     method : 'POST',
                     headers : headers,
                     body : options }, 
                   callback );
}

function bulkDelete( auth, parameters, callback ){
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/virtualCircuits' + encodeURIComponent(parameters.virtualCircuitId) +
                            '/actions/bulkDeletePublicPrefixes',
                     host : endpoint.service.core[auth.region],
                     headers : headers,
                     method : 'POST',
                     body : options }, 
                   callback );
}

function list( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['verificationState'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/virtualCircuits' + encodeURIComponent(parameters.virtualCircuitId) +
                            '/publicPrefixes' + queryString,
                     host : endpoint.service.core[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
};

module.exports = {
    list: list,
    bulkAdd: bulkAdd,
    bulkDelete: bulkDelete
    };
