var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'App Mesh Restrict External Traffic',
    category: 'App Mesh',
    domain: 'Content Delivery',
    description: 'Ensure that Amazon App Mesh virtual nodes have egress only access to other defined resources available within the service mesh.',
    more_info: 'Amazon App Mesh gives control over the traffic flow to configure the microservices. Getting the control will allow you to decide if you want to give access to outside world for communication or not.',
    link: 'https://docs.aws.amazon.com/app-mesh/latest/userguide/meshes.html',
    recommended_action: 'Enable the feature to allow egress only from virtual nodes to other defined resources in the service mesh.',
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
                    `Unable to query for App Meshes: ${helpers.addError(listMeshes)}`,region);
                return rcb();
            }

            if (!listMeshes.data.length) {
                helpers.addResult(results, 0, 'No App Meshes found', region);
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
                        `Unable to get App Mesh description: ${helpers.addError(describeMesh)}`,
                        region, resource);
                    continue;
                } 

                if (describeMesh.data.mesh.spec &&
                    describeMesh.data.mesh.spec.egressFilter &&
                    describeMesh.data.mesh.spec.egressFilter.type.toUpperCase() === 'DROP_ALL') {
                    helpers.addResult(results, 0,
                        'Amazon App Mesh allows egress only from virtual nodes to other defined resources.',
                        region, resource);
                    continue;         
                } else {
                    helpers.addResult(results, 2,
                        'Amazon App Mesh allows egress to any endpoint inside or outside of the service mesh.',
                        region, resource);
                    continue;
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};