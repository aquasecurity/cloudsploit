var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ){
  var possibleHeaders = ['iopc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/exports',
                     host : endpoint.service.fileStorage[auth.region],
                     method : 'POST',
                     headers : headers,
                     body : parameters.body }, 
                   callback );
}

function update( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/exports/' + encodeURIComponent(parameters.exportId),
                     host : endpoint.service.fileStorage[auth.region],
                     method : 'PUT',
                     headers : headers,
                     body : parameters.body },
                   callback );
}

function get( auth, parameters, callback ) {
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/exports/' + encodeURIComponent(parameters.exportId),
                     host : endpoint.service.fileStorage[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
}

function drop( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/exports/' + encodeURIComponent(parameters.exportId),
                     host : endpoint.service.fileStorage[auth.region],
                     headers : headers,
                     method : 'DELETE' },
                    callback );
}

module.exports = {
    update: update,
    get: get,
    create: create,
    drop: drop
    };
