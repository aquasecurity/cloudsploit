var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Binary Authorization Enabled',
    category: 'Kubernetes',
    domain: 'Containers',
    severity: 'Medium',
    description: 'Ensure Binary Authorization is enabled on Kubernetes Clusters',
    more_info: 'Binary authorization ensures that only trusted and signed container images are deployed within a kubernetes cluster. This provides tighter security control for images and container deployment. As a security best practice and to adhere to compliance standards, ensure this feature is enabled on all kubernetes clusters.',
    link: 'https://cloud.google.com/binary-authorization/docs/overview',
    recommended_action: 'Ensure binary authorization is enabled for all Kubernetes clusters',
    apis: ['kubernetes:list'],
    realtime_triggers: ['container.ClusterManager.CreateCluster', 'container.ClusterManager.DeleteCluster','container.ClusterManager.UpdateCluster'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0].name;

        async.each(regions.kubernetes, function(region, rcb){
            let clusters = helpers.addSource(cache, source,
                ['kubernetes', 'list', region]);

            if (!clusters) return rcb();

            if (clusters.err || !clusters.data) {
                helpers.addResult(results, 3, 'Unable to query Kubernetes clusters', region, null, null, clusters.err);
                return rcb();
            }

            if (!clusters.data.length) {
                helpers.addResult(results, 0, 'No Kubernetes clusters found', region);
                return rcb();
            }

            clusters.data.forEach(cluster => {
                let location;
                if (cluster.locations) {
                    location = cluster.locations.length === 1 ? cluster.locations[0] : cluster.locations[0].substring(0, cluster.locations[0].length - 2);
                } else location = region;

                let resource = helpers.createResourceName('clusters', cluster.name, project, 'location', location);

                if (cluster.binaryAuthorization && cluster.binaryAuthorization.evaluationMode
                    && cluster.binaryAuthorization.evaluationMode.toLowerCase() !== 'disabled') {
                    helpers.addResult(results, 0,
                        'Binary Authorization is enabled on the cluster', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Binary Authorization is not enabled on the cluster', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};