var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function get( auth, parameters, callback ) {
  var possibleQueryStrings = ['createdOnRangeEnd', 'createdOnRangeStart', 'expands', 'limit', 'modifiedOnRangeEnd',
                              'modifiedOnRangeStart', 'offset', 'operationItemAttributeName', 'operationItemAttributeValue',
                              'operationItemCurrentActions', 'operationItemDefinitionId', 'operationItemDefinitionIds',
                              'operationItemId', 'operationItemStatus', 'operationItemStatuses', 'orderBy', 'status',
                              'statuses', 'subSystem' ];
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  var possibleHeaders = ['x-id-tenant-name'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/itas/' + encodeURIComponent(parameters.domain) +
                            '/myservices/api' + auth.RESTversion +
                            '/operations' + queryString,
                     host : endpoint.service.myServices,
                     headers : headers,
                     method : 'GET' },
                    callback );
}

function post( auth, parameters, callback ) {
  var possibleHeaders = ['x-id-tenant-name'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/itas/' + encodeURIComponent(parameters.domain) +
                            '/myservices/api' + auth.RESTversion +
                            '/operations',
                     host : endpoint.service.myServices,
                     headers : headers,
                     body : parameters.body,
                     method : 'POST' },
                    callback );
}

module.exports = {
    get: get,
    post: post
    };