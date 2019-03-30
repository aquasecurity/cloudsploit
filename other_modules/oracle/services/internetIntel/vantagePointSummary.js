var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function list( auth, parameters, callback ){
  var possibleHeaders = [];
  var possibleQueryStrings = ['limit', 'page'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
    ocirest.process( auth,
                     { path : auth.RESTVersion + '/marketPerformance/vantagePoints' + queryString,
                       host : endpoint.service.internetIntel[auth.region],
                       headers : headers,
                       method : 'GET' },
                     callback );
  }

module.exports = {
  list: list
}