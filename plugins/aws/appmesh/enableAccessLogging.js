var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Enable Access Logging for App Mesh Virtual Gateways',
    category: 'App Mesh',
    domain: 'Content Delivery',
    description: 'Ensure that your Amazon App Mesh virtual gateways have access logging enabled and configured for all.',
    more_info: 'The Amazon App Mesh virtual gateways Access Logging feature provide evidence for security audits and investigations, it also lets you keep an eye on application mesh user access and helps you meet compliance regulations. ',
    link: 'https://docs.aws.amazon.com/app-mesh/latest/userguide/envoy-logs.html',
    recommended_action: 'Enable the feature, configure the file path to write access logs, within the virtual gateway configuration settings.',
    apis: ['AppMesh:listMeshes', 'AppMesh:listVirtualGateways', 'AppMesh:describeVirtualGateway'],
    

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.regions(settings);
        

        async.each(region.appmesh, function(region, rcb){
            var listMeshes = helpers.addSource(cache, source,
                ['appmesh', 'listMeshes', region]);
            
            if (!listMeshes) return rcb();

            if (listMeshes.err || !listMeshes.data) {
                helpers.addResult(results, 3,
                    'Unable to query for App Meshes: ' + helpers.addError(listMeshes),region);
                return rcb();
            }

            if (!listMeshes.data.length) {
                helpers.addResult(results, 0, 'No App Meshes found', region);
                return rcb();
            }

            for (let mesh of listMeshes.data){
                if (!mesh.arn) continue;

                let resource = mesh.arn;

                var listVirtualGateways = helpers.addSource(cache, source,
                    ['appmesh', 'listVirtualGateways', region, mesh.meshName]);

                if (!listVirtualGateways || listVirtualGateways.err || !listVirtualGateways.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for App Mesh virtual gateways: ' + helpers.addError(listVirtualGateways),
                        region, resource);
                    continue;
                }

                if (!listVirtualGateways.data.virtualGateways || !listVirtualGateways.data.virtualGateways.length) {
                    helpers.addResult(results, 0,
                        'No AppMesh virtual gateways found', region, resource);
                    continue;
                }

                for (let gateway of listVirtualGateways.data.virtualGateways) {
                    if (!gateway.arn) continue;

                    let resource = gateway.arn;

                    var describeVirtualGateway = helpers.addSource(cache, source,
                        ['appmesh', 'describeVirtualGateway', region, gateway.virtualGatewayName]);

                    if (!describeVirtualGateway ||
                        describeVirtualGateway.err ||
                        !describeVirtualGateway.data) {
                        helpers.addResult(results, 3,
                            'Unable to query AppMesh virtual gateway description: ' + helpers.addError(describeVirtualGateway), region, resource);
                        continue;
                    }

                    if (!describeVirtualGateway.data.virtualGateway ||
                        !describeVirtualGateway.data.virtualGateway.spec ||
                        !describeVirtualGateway.data.virtualGateway.spec.logging ||
                        !describeVirtualGateway.data.virtualGateway.spec.logging.accessLog ||
                        !describeVirtualGateway.data.virtualGateway.spec.logging.accessLog.file ||
                        !describeVirtualGateway.data.virtualGateway.spec.logging.accessLog.file.path) {
                        helpers.addResult(results, 2,
                            'access logging is not enabled for Amazon App Mesh virtual gateways',
                            region, resource);
                        continue;         
                    } else {
                        helpers.addResult(results, 0,
                            'access logging is enabled and configured for Amazon App Mesh virtual gateways',
                            region, resource);
                        continue;
                    }
                }
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};