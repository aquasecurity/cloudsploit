var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function update( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['compartmentId'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );

  ocirest.process( auth,
                   { path : auth.RESTversion + '/configuration' + queryString,
                     host : endpoint.service.core[auth.region],
                     method : 'PUT',
                     headers : headers,
                     body : parameters.body },
                   callback );
};

function get( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['compartmentId'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );

  ocirest.process( auth,
                   { path : auth.RESTversion + '/configuration' + queryString,
                     host : endpoint.service.audit[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
};

module.exports = {
    update: update,
    get: get
    };
