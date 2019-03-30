var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ){
  var possibleHeaders = ['opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/volumes',
                     host : endpoint.service.core[auth.region],
                     method : 'POST',
                     headers : headers,
                     body : options }, 
                   callback );
}

function update( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/volumes/' + encodeURIComponent(parameters.volumeId),
                     host : endpoint.service.core[auth.region],
                     method : 'PUT',
                     headers : headers,
                     body : options },
                   callback );
};

function get( auth, parameters, callback ) {
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/volumes/' + encodeURIComponent(parameters.volumeId),
                     host : endpoint.service.core[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
};

function drop( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/volumes/' + encodeURIComponent(parameters.volumeId),
                     host : endpoint.service.core[auth.region],
                     headers : headers,
                     method : 'DELETE' },
                    callback );
};

function detatch( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/volumeAttachments/' + encodeURIComponent(parameters.volumeAttachmentId),
                     host : endpoint.service.core[auth.region],
                     headers : headers,
                     method : 'DELETE' },
                    callback );
};


function list( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['availabilityDomain', 'compartmentId', 'displayName', 'limit', 'page', 
                              'volumeGroupId', 'sortBy', 'sortOrder', 'lifecycleState'];
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
    update: update,
    get: get,
    create: create,
    drop: drop,
    detatch: detatch
    };
