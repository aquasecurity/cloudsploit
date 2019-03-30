var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function add( auth, parameters, callback ) {
  var possibleHeaders = ['opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + '/userGroupMemberships/',
                       host : endpoint.service.iam[auth.region],
                       method : 'POST',
                       body : parameters.body,
                       headers : headers },
                      callback )
  };

function remove( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth,
                     { path : auth.RESTversion + 
                              '/userGroupMemberships/' + encodeURIComponent(parameters.userGroupMembershipId),
                       host : endpoint.service.iam[auth.region],
                       method : 'DELETE',
                       headers : headers },
                      callback )
  };

function get( auth, parameters, callback ) {
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
    ocirest.process( auth, 
                     { path : auth.RESTversion + 
                              '/userGroupMemberships/' + encodeURIComponent(parameters.userGroupMembershipId),
                       host : endpoint.service.iam[auth.region],
                       headers : headers,
                       method : 'GET' }, 
                     callback );
  };

function list( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['compartmentId', 'userId', 'groupId', 'page', 'limit'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
    ocirest.process( auth, 
                     { path : auth.RESTversion + '/userGroupMemberships/' + queryString,
                       host : endpoint.service.iam[auth.region],
                       headers : headers,
                       method : 'GET' }, 
                     callback );
  };

  module.exports={
      list: list,
      remove: remove,
      add: add,
      get: get
  }