var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'DocumentDB Has Tags',
    category: 'DocumentDB',
    domain: 'Databases',
    severity: 'Low',
    description: 'Ensure that AWS DocumentDB clusters have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify DocumentDB cluster and add tags.',
    link: 'https://docs.aws.amazon.com/documentdb/latest/developerguide/tagging.html',
    apis: ['DocDB:describeDBClusters', 'DocDB:listTagsForResource'],
    realtime_triggers: ['docdb:CreateDBCluster','docdb:CreateDBInstance','docdb:DeleteDBCluster', 'docdb:ModifyDBCluster'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

    
        async.each(regions.docdb, function(region, rcb){
            var describeDBClusters = helpers.addSource(cache, source,
                ['docdb', 'describeDBClusters', region]);

            if (!describeDBClusters) return rcb();

            if (describeDBClusters.err || !describeDBClusters.data) {
                helpers.addResult(results, 3,
                    `Unable to list DocumentDB clusters: ${helpers.addError(describeDBClusters)}`, region);
                return rcb();
            }

            if (!describeDBClusters.data.length) {
                helpers.addResult(results, 0,
                    'No DocumentDB clusters found', region);
                return rcb();
            }
            for (let cluster of describeDBClusters.data){
                if (!cluster.DBClusterArn) continue;
               
                let resource = cluster.DBClusterArn;

                let getTags = helpers.addSource(cache, source,
                    ['docdb', 'listTagsForResource', region, resource]);

                if (!getTags || !getTags.data || getTags.err) {
                    helpers.addResult(results, 3, `Unable to get tags information for doc db cluster: ${helpers.addError(getTags)}`, region, resource);
                    continue;
                }
    
                if (getTags.data.TagList && Object.entries(getTags.data.TagList).length > 0) {
                    helpers.addResult(results, 0, 'DocumentDB cluster has tags associated', region, resource);
                } else {
                    helpers.addResult(results, 2, 'DocumentDB cluster does not have tags associated', region, resource);
                }
            }
            
            rcb();

        }, function(){
            callback(null, results, source);
        });
    }
}; 