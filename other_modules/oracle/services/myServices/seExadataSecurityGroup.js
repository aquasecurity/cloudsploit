var ocirest = require('../../utils/ocirest.js');
var endpoint = require('../../configs/endpoints.js');

function drop( auth, parameters, callback ) {
  var possibleHeaders = ['x-id-tenant-name'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/itas/' + encodeURIComponent(parameters.domain) +
                            '/myservices/api' + auth.RESTversion +
                            '/serviceEntitlements/' + encodeURIComponent(parameters.serviceEntitlementId) +
                            '/serviceConfigurations/' + encodeURIComponent(parameters.serviceConfigurationId) +
                            '/securityGroups/' + encodeURIComponent(parameters.id),
                     host : endpoint.service.myServices,
                     headers : headers,
                     method : 'DELETE' },
                    callback );
};

function get( auth, parameters, callback ) {
  var possibleHeaders = ['x-id-tenant-name'];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/itas/' + encodeURIComponent(parameters.domain) +
                            '/myservices/api' + auth.RESTversion +
                            '/serviceEntitlements/' + encodeURIComponent(parameters.serviceEntitlementId) +
                            '/serviceConfigurations/' + encodeURIComponent(parameters.serviceConfigurationId) +
                            '/securityGroups/' + encodeURIComponent(parameters.id),
                     host : endpoint.service.myServices,
                     headers : headers,
                     method : 'GET' },
                    callback );
};

function put( auth, parameters, callback ) {
  var possibleHeaders = [];
  var headers = ocirest.buildHeaders( possibleHeaders, parameters );
  ocirest.process( auth,
                   { path : '/itas/' + encodeURIComponent(parameters.domain) +
                            '/myservices/api' + auth.RESTversion +
                            '/serviceEntitlements/' + encodeURIComponent(parameters.serviceEntitlementId) +
                            '/serviceConfigurations/' + encodeURIComponent(parameters.serviceConfigurationId) +
                            '/securityGroups/' + encodeURIComponent(parameters.id),
                     host : endpoint.service.myServices,
                     headers : headers,
                     body : parameters.body,
                     method : 'PUT' },
                    callback );
};



module.exports = {
    drop: drop,
    get: get,
    put: put
    };