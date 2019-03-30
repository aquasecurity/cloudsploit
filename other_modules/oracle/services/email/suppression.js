var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ){
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/suppressions',
                     host : endpoint.service.email[auth.region],
                     headers : headers,
                     method : 'POST',
                     body : parameters.body }, 
                   callback );
}

function get( auth, parameters, callback ) {
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/suppressions/' + encodeURIComponent(parameters.suppressionId),
                     host : endpoint.service.email[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
};

function drop( auth, parameters, callback ) {
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/suppressions/' + encodeURIComponent(parameters.suppressionId),
                     host : endpoint.service.email[auth.region],
                     headers : headers,
                     method : 'DELETE' },
                    callback );
};

module.exports = {
    get: get,
    create: create,
    drop: drop
    };
