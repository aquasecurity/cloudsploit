var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function list( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['compartmentId', 'availabilityDomain', 'limit', 'page', 'imageId'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
    ocirest.process( auth, 
                     { path : auth.RESTversion + '/shapes' + queryString,
                       host : endpoint.service.core[auth.region],
                       headers : headers,
                       method : 'GET' }, 
                     callback );
  };

  module.exports={
    list: list
  }