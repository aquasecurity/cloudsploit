var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'App Mesh Restrict External Traffic',
    category: 'App Mesh',
    domain: 'Content Delivery',
    description: 'Ensure that Amazon App Mesh virtual nodes have egress only access to other defined resources available within the service mesh.',
    more_info: 'Amazon App Mesh gives you controls to choose whether or not to allow App Mesh services to communicate with outside world. ' +
        'If you choose to deny external traffic, the proxies will not forward traffic to external services not defined in the mesh. ' +
        'The traffic to the external services should be denied to adhere to cloud security best practices and minimize the security risks.',
    link: 'https://docs.aws.amazon.com/app-mesh/latest/userguide/security.html',
    recommended_action: 'Deny all traffic to the external services',
    apis: ['AppMesh:listMeshes', 'AppMesh:describeMesh'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.appmesh, function(region, rcb){        
            var listMeshes = helpers.addSource(cache, source,
                ['appmesh', 'listMeshes', region]);

            if (!listMeshes) return rcb();

            if (listMeshes.err || !listMeshes.data) {
                helpers.addResult(results, 3,
                    `Unable to query for App Mesh meshes: ${helpers.addError(listMeshes)}`,region);
                return rcb();
            }

            if (!listMeshes.data.length) {
                helpers.addResult(results, 0, 'No App Mesh meshes found', region);
                return rcb();
            }

            for (let mesh of listMeshes.data) {
                if (!mesh.arn) continue;

                let resource = mesh.arn;

                var describeMesh = helpers.addSource(cache, source,
                    ['appmesh', 'describeMesh', region, mesh.meshName]);

                if (!describeMesh || describeMesh.err || !describeMesh.data ||
                    !describeMesh.data.mesh) {
                    helpers.addResult(results, 3,
                        `Unable to describe App Mesh mesh: ${helpers.addError(describeMesh)}`,
                        region, resource);
                    continue;
                } 

                if (describeMesh.data.mesh.spec &&
                    describeMesh.data.mesh.spec.egressFilter &&
                    describeMesh.data.mesh.spec.egressFilter.type.toUpperCase() === 'ALLOW_ALL') {
                    helpers.addResult(results, 2,
                        'App Mesh mesh allows access to external services',
                        region, resource);       
                } else {
                    helpers.addResult(results, 0,
                        'App Mesh mesh does not allow access to external services',
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};