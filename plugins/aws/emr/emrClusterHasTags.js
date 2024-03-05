var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EMR Cluster Has Tags',
    category: 'EMR',
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensure that EMR clusters have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-plan-tags-add-new.html',
    recommended_action: 'Modify EMR cluster and add tags.',
    apis: ['EMR:listClusters', 'EMR:describeCluster'],
    realtime_triggers: ['emr:CreateCluster', 'emr:AddTags', 'emr:RemoveTags', 'emr:TerminateClusters'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.emr, function(region, rcb){
            var listClusters = helpers.addSource(cache, source,
                ['emr', 'listClusters', region]);
                
            if (!listClusters) return rcb();

            if (listClusters.err || !listClusters.data) {
                helpers.addResult(results, 3,
                    'Unable to query for EMR clusters: ' + helpers.addError(listClusters), region);
                return rcb();
            }

            if (!listClusters.data.length) {
                helpers.addResult(results, 0, 'No EMR clusters found', region);
                return rcb();
            }

            for (var cluster of listClusters.data) {
                if (!cluster.Id) continue;
                
                var resource = cluster.ClusterArn;

                var describeCluster = helpers.addSource(cache, source,
                    ['emr', 'describeCluster', region, cluster.Id]);
            
                if (!describeCluster || describeCluster.err || !describeCluster.data || !describeCluster.data.Cluster) {
                    helpers.addResult(results, 3,
                        'Unable to query for EMR cluster', region, resource);
                    continue;
                }
                var clusterTags = describeCluster.data.Cluster.Tags;

                if (!clusterTags || !clusterTags.length) {
                    helpers.addResult(results, 2, 'EMR cluster does not have tags', region, resource);
                }  else {
                    helpers.addResult(results, 0, 'EMR cluster has tags', region, resource);
                }
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};

