var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Cluster Labels Added',
    category: 'Kubernetes',
    description: 'Ensures all Kubernetes clusters have labels added',
    more_info: 'It is recommended to add labels to Kubernetes clusters to apply specific security settings and auto configure objects at creation.',
    link: 'https://cloud.google.com/kubernetes-engine/docs/how-to/creating-managing-labels',
    recommended_action: 'Ensure labels are added to Kubernetes clusters',
    apis: ['clusters:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.clusters, function(region, rcb){
            let clusters = helpers.addSource(cache, source,
                ['clusters', 'list', region]);

            if (!clusters) return rcb();

            if (clusters.err || !clusters.data) {
                helpers.addResult(results, 3, 'Unable to query Kubernetes clusters: ' + helpers.addError(clusters), region);
                return rcb();
            }

            if (!clusters.data.length) {
                helpers.addResult(results, 0, 'No Kubernetes clusters found', region);
                return rcb();
            }

            clusters.data.forEach(cluster => {
                if (cluster.resourceLabels &&
                    Object.keys(cluster.resourceLabels).length) {
                    helpers.addResult(results, 0,
                        `${Object.keys(cluster.resourceLabels).length} labels found for the cluster.`, region, cluster.name);
                } else {
                    helpers.addResult(results, 2,
                        'The cluster does not have any labels added.', region, cluster.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};