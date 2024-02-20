var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'App Mesh VG Health Check Policies',
    category: 'App Mesh',
    domain: 'Content Delivery',
    severity: 'Medium',
    description: 'Ensure that Amazon App Mesh virtual gateways use health check policies to monitor the availability of virtual nodes.',
    more_info: 'Health check policies in App Mesh are essential to maintain application availability and reliability by monitoring the health of associated virtual nodes.',
    link: 'https://docs.aws.amazon.com/app-mesh/latest/userguide/virtual_gateway_health_checks.html',
    recommended_action: 'Configure health check policies for the virtual gateway listeners in your App Mesh, specifying values for healthy threshold, health check interval, health check protocol, timeout period, and unhealthy threshold.',
    apis: ['AppMesh:listMeshes', 'AppMesh:listVirtualGateways', 'AppMesh:describeVirtualGateway'],
    realtime_triggers: ['appmesh:CreateMesh','appmesh:DeleteMesh','appmesh:CreateVirtualGateway','appmesh:UpdateVirtualGateway','appmesh:DeleteVirtualGateway'],
   
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.regions(settings);

        async.each(region.appmesh, function(region, rcb) {
            var listMeshes = helpers.addSource(cache, source,
                ['appmesh', 'listMeshes', region]);

            if (!listMeshes) return rcb();

            if (listMeshes.err || !listMeshes.data) {
                helpers.addResult(results, 3,
                    'Unable to query for App Mesh meshes: ' + helpers.addError(listMeshes), region);
                return rcb();
            }

            if (!listMeshes.data.length) {
                helpers.addResult(results, 0, 'No App Mesh meshes found', region);
                return rcb();
            }

            for (let mesh of listMeshes.data){
                if (!mesh.arn || !mesh.meshName) continue;

                let meshResource = mesh.arn;

                var listVirtualGateways = helpers.addSource(cache, source,
                    ['appmesh', 'listVirtualGateways', region, mesh.meshName]);

                if (!listVirtualGateways || listVirtualGateways.err || !listVirtualGateways.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for App Mesh virtual gateways: ' + helpers.addError(listVirtualGateways),
                        region, meshResource);
                    continue;
                }

                if (!listVirtualGateways.data.virtualGateways || !listVirtualGateways.data.virtualGateways.length) {
                    helpers.addResult(results, 0,
                        'No App Mesh virtual gateways found', region, meshResource);
                    continue;
                }

                for (let gateway of listVirtualGateways.data.virtualGateways) {
                    if (!gateway.arn || !gateway.virtualGatewayName) continue;

                    let gatewayResource = gateway.arn;

                    var describeVirtualGateway = helpers.addSource(cache, source,
                        ['appmesh', 'describeVirtualGateway', region, gateway.virtualGatewayName]);

                    if (!describeVirtualGateway ||
                        describeVirtualGateway.err ||
                        !describeVirtualGateway.data) {
                        helpers.addResult(results, 3,
                            'Unable to describe App Mesh virtual gateway: ' + helpers.addError(describeVirtualGateway), region, gatewayResource);
                        continue;
                    }
                    if (!describeVirtualGateway.data.virtualGateway.spec ||
                        !describeVirtualGateway.data.virtualGateway.spec.listeners ||
                        !describeVirtualGateway.data.virtualGateway.spec.listeners.length) {
                        helpers.addResult(results, 0,
                            'App Mesh virtual gateway does not have listeners', region, gatewayResource);
                    } else {
                        const listeners = describeVirtualGateway.data.virtualGateway.spec.listeners;
                        const hasHealthCheckPolicies = listeners.every(listener => {
                            return listener.healthCheck && Object.keys(listener.healthCheck).length;
                        });
                        const status = hasHealthCheckPolicies ? 0 : 2;
                        helpers.addResult(results, status,
                            `App Mesh virtual gateway ${hasHealthCheckPolicies ? 'has' : 'does not have'} health check policies`,
                            region, gatewayResource);
                    }
                }
            }
            
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
