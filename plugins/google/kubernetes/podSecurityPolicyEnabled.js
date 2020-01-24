var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Pod Security Policy Enabled',
    category: 'Kubernetes',
    description: 'Ensures pod security policy is enabled for all Kubernetes clusters',
    more_info: 'Kubernetes pod security policy is a resource that controls security sensitive aspects of the pod configuration.',
    link: 'https://cloud.google.com/kubernetes-engine/docs/how-to/pod-security-policies',
    recommended_action: 'Ensure that all Kubernetes clusters have pod security policy enabled.',
    apis: ['clusters:list'],

    run: function(cache, settings, callback) {

        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.clusters, (region, rcb) => {
            var clusters = helpers.addSource(cache, source,
                ['clusters', 'list', region]);

            if (!clusters) return rcb();

            if (clusters.err || !clusters.data) {
                helpers.addResult(results, 3,
                    'Unable to query for clusters: ' + helpers.addError(clusters), region);
                return rcb();
            }

            if (!clusters.data.length) {
                helpers.addResult(results, 0, 'No clusters found', region);
                return rcb();
            }

            clusters.data.forEach(cluster => {
                if (cluster.podSecurityPolicyConfig &&
                    cluster.podSecurityPolicyConfig.enabled) {
                    helpers.addResult(results, 0, 'Pod security policy config is enabled', region, cluster.name);
                } else {
                    helpers.addResult(results, 2, 'Pod security policy config is disabled', region, cluster.name);
                }
            });
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};