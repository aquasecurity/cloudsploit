var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function list( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['compartmentId', 'limit', 'page', 'includeSubCompartments'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
    ocirest.process( auth, 
                     { path : auth.RESTversion + 
                              '/tagNamespaces/' + encodeURIComponent(parameters.policyId) +
                              queryString,
                       host : endpoint.service.iam[auth.region],
                       headers : headers,
                       method : 'GET' }, 
                     callback );
  };

  module.exports={
      list: list
  }