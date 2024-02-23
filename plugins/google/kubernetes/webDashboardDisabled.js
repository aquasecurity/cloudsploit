var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Web Dashboard Disabled',
    category: 'Kubernetes',
    domain: 'Containers',
    severity: 'High',
    description: 'Ensures all Kubernetes clusters have the web dashboard disabled.',
    more_info: 'It is recommended to disable the web dashboard because it is backed by a highly privileged service account.',
    link: 'https://cloud.google.com/kubernetes-engine/docs/concepts/dashboards',
    recommended_action: 'Ensure that no Kubernetes clusters have the web dashboard enabled',
    apis: ['kubernetes:list'],
    realtime_triggers: ['container.clustermanager.createcluster','container.clustermanager.deletecluster'],
    
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

                if (cluster.addonsConfig &&
                    cluster.addonsConfig.kubernetesDashboard &&
                    cluster.addonsConfig.kubernetesDashboard.disabled) {
                    helpers.addResult(results, 0,
                        'The web dashboard is disabled for the Kubernetes cluster', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'The web dashboard is enabled for the Kubernetes cluster', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};