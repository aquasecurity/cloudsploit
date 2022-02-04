var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'App Mesh VG Access Logging',
    category: 'App Mesh',
    domain: 'Content Delivery',
    description: 'Ensure that your Amazon App Mesh virtual gateways have access logging enabled.',
    more_info: 'The Amazon App Mesh virtual gateways Access Logging feature provide evidence for security audits and investigations as well as let\'s you keep an eye on application mesh user access and helps you meet compliance regulations. ',
    link: 'https://docs.aws.amazon.com/app-mesh/latest/userguide/envoy-logs.html',
    recommended_action: 'Modify App Mesh virtual gateways to configure access logging feature',
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
                    'Unable to query for App Mesh meshes: ' + helpers.addError(listMeshes),region);
                return rcb();
            }

            if (!listMeshes.data.length) {
                helpers.addResult(results, 0, 'No App Mesh meshes found', region);
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

                if (!listVirtualGateways.data.virtualGateways) {
                    helpers.addResult(results, 0,
                        'No App Mesh virtual gateways found', region, resource);
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
                            'Unable to describe App Mesh virtual gateway: ' + helpers.addError(describeVirtualGateway), region, resource);
                        continue;
                    }

                    if (describeVirtualGateway.data.virtualGateway &&
                        describeVirtualGateway.data.virtualGateway.spec &&
                        describeVirtualGateway.data.virtualGateway.spec.logging &&
                        describeVirtualGateway.data.virtualGateway.spec.logging.accessLog &&
                        describeVirtualGateway.data.virtualGateway.spec.logging.accessLog.file &&
                        describeVirtualGateway.data.virtualGateway.spec.logging.accessLog.file.path &&
                        describeVirtualGateway.data.virtualGateway.spec.logging.accessLog.file.path.length) {
                        helpers.addResult(results, 0,
                            'App Mesh virtual gateway has access logging enabled',
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'App Mesh virtual gateway does not have access logging enabled',
                            region, resource);
                    }
                }
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};