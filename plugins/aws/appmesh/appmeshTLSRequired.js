var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'App Mesh TLS Required',
    category: 'App Mesh',
    domain: 'Content Delivery',
    description: 'Ensure that AWS App Mesh virtual gateways Listener only accepts connections with TLS enabled.',
    more_info: 'In App Mesh, Transport Layer Security (TLS) encrypts communication between the Envoy proxies deployed on compute resources that are represented in App Mesh by mesh endpoints. An object that represents the Transport Layer Security (TLS) properties for a listener.',
    link: 'https://docs.aws.amazon.com/app-mesh/latest/APIReference/API_ListenerTls.html',
    recommended_action: 'Restrict TLS enabled connections to AWS App Mesh virtual gateways Listeners in your account',
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
                        !describeVirtualGateway.data || describeVirtualGateway.data.virtualGateway) {
                        helpers.addResult(results, 3,
                            'Unable to App Mesh virtual gateways: ' + helpers.addError(describeVirtualGateway), region, gatewayArn);
                        continue;
                    }

                    let virtual = describeVirtualGateway.data.virtualGateway;
                   
                    if (!virtual.spec.listeners.length) {
                        helpers.addResult(results, 0,
                            'App Mesh virtual gateway does not have listeners', region, gatewayArn);
                    } else {
                        const tlsEnabled = virtual.spec.listeners.every(listener => listener.tls && listener.tls.mode && listener.tls.mode.toUpperCase() === 'STRICT');
                        const status = tlsEnabled ? 0 : 2;
                        helpers.addResult(results, status,
                            `App Mesh virtual gateway listeners ${tlsEnabled ? 'restrict ' : 'does not restrict '} TLS enabled connections`,
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