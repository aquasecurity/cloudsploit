var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Client Certificate Disabled',
    category: 'Kubernetes',
    domain: 'Containers',
    severity: 'High',
    description: 'Ensure client certificate authentication to Kubernetes clusters is disabled.',
    more_info: 'In authentication using client certificates, the client presents a certificate signed by cluster root certificate authority which is only base64 encoded and not encrypted. The client certificate authentication method is considered legacy and cause potential security risks. It is recommended to use the default GKE OAuth method for authentication.',
    link: 'https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#restrict_authn_methods',
    recommended_action: 'Ensure no kubernetes clusters are using client certificates for authentication',
    apis: ['kubernetes:list'],
    realtime_triggers: ['container.ClusterManager.CreateCluster', 'container.ClusterManager.DeleteCluster'],

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

                if (cluster.masterAuth && cluster.masterAuth.clientCertificate) {
                    helpers.addResult(results, 2,
                        'Cluster is using client certificate for authentication', region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'Cluster is not using client certificate for authentication', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};