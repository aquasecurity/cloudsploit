var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function create( auth, parameters, callback ) {
  var possibleHeaders = ['opc-retry-token'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/compartments/',
                     host : endpoint.service.iam[auth.region],
                     method : 'POST',
                     body : parameters.body,
                     headers : headers },
                    callback )
  }

function get( auth, parameters, callback ) {
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : auth.RESTversion + '/compartments/' + encodeURIComponent(parameters.compartmentId),
                     host : endpoint.service.iam[auth.region],
                     headers : headers,
                     method : 'GET' },
                    callback )
  }

function list( auth, parameters, callback ) {
  var possibleHeaders = [];
  var possibleQueryStrings = ['compartmentId','page','limit','accessLevel','compartmentIdInSubtree'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  var queryString = ocirest.buildQueryString( possibleQueryStrings, parameters );
  ocirest.process( auth, 
                   { path : auth.RESTversion + '/compartments/' + queryString,
                     host : endpoint.service.iam[auth.region],
                     headers : headers,
                     method : 'GET' }, 
                   callback );
  }

function update( auth, parameters, callback ) {
  var possibleHeaders = ['if-match'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth, 
                   { path : auth.RESTversion + 
                            '/compartments/' + encodeURIComponent(parameters.compartmentId),
                     host : endpoint.service.iam[auth.region],
                     headers : headers,
                     body : parameters.body,
                     method : 'PUT' }, 
                   callback );
  }

  module.exports={
      list: list,
      update: update,
      create: create,
      get: get
  }