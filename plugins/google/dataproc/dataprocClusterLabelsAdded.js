var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Dataproc Cluster Labels Added',
    category: 'Dataproc',
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensure that all Dataproc clusters have labels added.',
    more_info: 'Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.',
    link: 'https://cloud.google.com/dataproc/docs/guides/creating-managing-labels',
    recommended_action: 'Ensure labels are added to all Dataproc clusters.',
    apis: ['dataproc:list'],
    realtime_triggers: ['dataproc.ClusterController.CreateCluster', 'dataprocClusterController.DeleteCluster', 'dataproc.ClusterController.UpdateCluster'],

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

        async.each(regions.dataproc, function(region, rcb){
            let clusters = helpers.addSource(cache, source,
                ['dataproc' ,'list', region]);

            if (!clusters) return rcb();

            if (clusters.err || !clusters.data) {
                helpers.addResult(results, 3, 'Unable to query Dataproc clusters', region, null, null, clusters.err);
                return rcb();
            }

            if (!clusters.data.length) {
                helpers.addResult(results, 0, 'No Dataproc clusters found', region);
                return rcb();
            }

            clusters.data.forEach(cluster => {
                if (!cluster.clusterName) return;

                let resource = helpers.createResourceName('clusters', cluster.clusterName, project, 'region', region);

                if (cluster.labels &&
                    Object.keys(cluster.labels).length) {
                    helpers.addResult(results, 0,
                        `${Object.keys(cluster.labels).length} labels found for Dataproc cluster`, region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Dataproc cluster does not have any labels', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};