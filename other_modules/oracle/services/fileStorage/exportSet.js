var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function update( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/exportSets/' + encodeURIComponent(parameters.exportSetId),
                     host : endpoint.service.fileStorage[auth.region],
                     method : 'PUT',
                     headers : headers,
                     body : parameters.body },
                   callback );
};

function get( auth, parameters, callback ) {
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/exportSets/' + encodeURIComponent(parameters.exportSetId),
                     host : endpoint.service.fileStorage[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback );
};

module.exports = {
    update: update,
    get: get
    };
