var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Cluster Least Privilege',
    category: 'Kubernetes',
    description: 'Ensures Kubernetes clusters are created with limited service account access scopes',
    more_info: 'Kubernetes service accounts should be limited in scope to the services necessary to operate the clusters.',
    link: 'https://cloud.google.com/compute/docs/access/service-accounts',
    recommended_action: 'Ensure that all Kubernetes clusters are created with limited access scope.',
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

            const minimalAccess = [
                'https://www.googleapis.com/auth/devstorage.read_only',
                'https://www.googleapis.com/auth/logging.write',
                'https://www.googleapis.com/auth/monitoring',
                'https://www.googleapis.com/auth/servicecontrol',
                'https://www.googleapis.com/auth/service.management.readonly',
                'https://www.googleapis.com/auth/trace.append'
            ];

            let otherScope = false;

            clusters.data.forEach(cluster => {
                if (cluster.nodeConfig &&
                    cluster.nodeConfig.serviceAccount &&
                    cluster.nodeConfig.serviceAccount == 'default') {
                    cluster.nodeConfig.oauthScopes.forEach((oneScope) => {
                        let sameExist= false;

                        for (let i = 0; i < minimalAccess.length; i++) {
                            if (oneScope == minimalAccess[i]) {
                                sameExist = true;
                            }
                        }
                        if (sameExist == false) {
                            otherScope = true;
                        }
                    });
                }
                if (otherScope == true) {
                    helpers.addResult(results, 2, 'No minimal access is allowed on Kubernetes cluster', region, cluster.name);
                } else {
                    helpers.addResult(results, 0, 'Minimal access is allowed on Kubernetes cluster', region, cluster.name);
                }
            });
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
}; 