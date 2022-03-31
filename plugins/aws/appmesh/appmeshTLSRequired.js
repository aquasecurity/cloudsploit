var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'App Mesh TLS Required',
    category: 'App Mesh',
    domain: 'Content Delivery',
    description: 'Ensure that AWS App Mesh virtual gateway listeners only accepts TLS enabled connections.',
    more_info: 'In App Mesh, Transport Layer Security (TLS) encrypts communication between the envoy proxies deployed on compute resources that are represented in App Mesh by mesh endpoints, such as Virtual nodes and Virtual gateways.',
    link: 'https://docs.aws.amazon.com/app-mesh/latest/APIReference/API_ListenerTls.html',
    recommended_action: 'Restrict AWS App Mesh virtual gateway listeners to accept only TLS enabled connections.',
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
                    'Unable to list App Mesh meshes: ' + helpers.addError(listMeshes),region);
                return rcb();
            }

            if (!listMeshes.data.length) {
                helpers.addResult(results, 0, 'No App Mesh meshes found', region);
                return rcb();
            }

            for (let mesh of listMeshes.data){
                if (!mesh.meshName || !mesh.arn) continue;

                let resource = mesh.arn;

                var listVirtualGateways = helpers.addSource(cache, source,
                    ['appmesh', 'listVirtualGateways', region, mesh.meshName]);

                if (!listVirtualGateways || listVirtualGateways.err || !listVirtualGateways.data) {
                    helpers.addResult(results, 3,
                        'Unable to list App Mesh virtual gateways: ' + mesh.meshName + ': ' + helpers.addError(listVirtualGateways),
                        region, resource);
                    continue;
                }

                if (!listVirtualGateways.data.virtualGateways || !listVirtualGateways.data.virtualGateways.length) {
                    helpers.addResult(results, 0,
                        'No App Mesh virtual gateways found', region, resource);
                    continue;
                }

                for (let gateway of listVirtualGateways.data.virtualGateways) {
                    if (!gateway.virtualGatewayName || !gateway.arn) continue;

                    var gatewayArn = gateway.arn;

                    var describeVirtualGateway = helpers.addSource(cache, source,
                        ['appmesh', 'describeVirtualGateway', region, gateway.virtualGatewayName]);

                    if (!describeVirtualGateway ||
                        describeVirtualGateway.err ||
                        !describeVirtualGateway.data) {
                        helpers.addResult(results, 3,
                            'Unable to describe App Mesh virtual gateway: ' + helpers.addError(describeVirtualGateway), region, gatewayArn);
                        continue;
                    }

                    if (!describeVirtualGateway.data.virtualGateway.spec ||
                        !describeVirtualGateway.data.virtualGateway.spec.listeners ||
                        !describeVirtualGateway.data.virtualGateway.spec.listeners.length) {
                        helpers.addResult(results, 0,
                            'App Mesh virtual gateway does not have listeners', region, gatewayArn);
                    } else {
                        const tlsEnabled = describeVirtualGateway.data.virtualGateway.spec.listeners.every(listener => listener.tls && listener.tls.mode && listener.tls.mode.toUpperCase() === 'STRICT');
                        const status = tlsEnabled ? 0 : 2;
                        helpers.addResult(results, status,
                            `App Mesh virtual gateway listeners ${tlsEnabled ? 'restrict' : 'does not restrict'} TLS enabled connections`,
                            region, gatewayArn);
                    }
                }
                
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};