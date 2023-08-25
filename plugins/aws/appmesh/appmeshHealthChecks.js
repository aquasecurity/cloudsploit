var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'App Mesh Virtual Gateway Health Check',
    category: 'App Mesh',
    domain: 'Reliability',
    description: 'Ensure that Amazon App Mesh virtual gateways use health check policies to monitor virtual node availability.',
    more_info: 'Health checks in App Mesh are used to probe the virtual gateway\'s ability to handle requests, increasing application availability and reliability.',
    link: 'https://docs.aws.amazon.com/app-mesh/latest/userguide/virtual_gateway_health_checks.html',
    recommended_action: 'Configure health check policies for the virtual gateway listeners in your App Mesh, specifying values for healthy threshold, health check interval, health check protocol, timeout period, and unhealthy threshold.',
    apis: ['AppMesh:describeVirtualGateway'],
   
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.regions(settings);
  
        async.each(region.appmesh, function(region, rcb) {
            var describeVirtualGateways = helpers.addSource(cache, source,
                ['appmesh', 'listVirtualGateways', region]);

            if (!describeVirtualGateways || describeVirtualGateways.err || !describeVirtualGateways.data) {
                helpers.addResult(results, 3,
                    'Unable to list App Mesh virtual gateways: ' + helpers.addError(describeVirtualGateways),
                    region);
                return rcb();
            }

            for (let virtualGateway of describeVirtualGateways.data.virtualGateways) {
                if (!virtualGateway.virtualGatewayName || !virtualGateway.arn) continue;

                var describeVirtualGateway = helpers.addSource(cache, source,
                    ['appmesh', 'describeVirtualGateway', region, virtualGateway.virtualGatewayName]);

                if (!describeVirtualGateway || describeVirtualGateway.err || !describeVirtualGateway.data) {
                    helpers.addResult(results, 3,
                        'Unable to describe App Mesh virtual gateway: ' + helpers.addError(describeVirtualGateway),
                        region, virtualGateway.arn);
                    continue;
                }

                if (!describeVirtualGateway.data.virtualGateway.spec ||
                    !describeVirtualGateway.data.virtualGateway.spec.listeners ||
                    !describeVirtualGateway.data.virtualGateway.spec.listeners.length) {
                    helpers.addResult(results, 0,
                        'App Mesh virtual gateway does not have listeners', region, virtualGateway.arn);
                } else {
                    const listeners = describeVirtualGateway.data.virtualGateway.spec.listeners;

                    const hasHealthCheckPolicies = listeners.every(listener => {
                        return listener.healthCheck && listener.healthCheck.protocol &&
                            listener.healthCheck.healthyThreshold && listener.healthCheck.intervalMillis &&
                            listener.healthCheck.timeoutMillis && listener.healthCheck.unhealthyThreshold;
                    });

                    const status = hasHealthCheckPolicies ? 0 : 2;
                    helpers.addResult(results, status,
                        `App Mesh virtual gateway ${hasHealthCheckPolicies ? 'has' : 'does not have'} health check policies`,
                        region, virtualGateway.arn);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
