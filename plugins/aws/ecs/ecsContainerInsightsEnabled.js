var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Container Insights Enabled',
    category: 'ECS',
    domain: 'Containers',
    severity: 'Low',
    description: 'Ensure that ECS clusters have CloudWatch Container Insights feature enabled.',
    more_info: 'CloudWatch Container Insights provides monitoring and troubleshooting solution for containerized applications and microservices that collects, aggregates and summarizes resource utilization such as CPU, memory, disk, and network.',
    recommended_action: 'Enabled container insights feature for ECS clusters.',
    link: 'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/cloudwatch-container-insights.html',
    apis: ['ECS:listClusters', 'ECS:describeCluster'],
    realtime_triggers: ['ecs:CreateCluster', 'ecs:UpdateClusterSettings', 'ecs:DeleteCluster'],

    run: function(cache, settings, callback){
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ecs, function(region, rcb){

            var listClusters = helpers.addSource(cache, source, 
                ['ecs','listClusters',region]);
            if (!listClusters) return rcb();

            if (listClusters.err || !listClusters.data) {
                helpers.addResult(results, 3, 
                    'Unable to query for ECS clusters: ' + helpers.addError(listClusters), region);
                return rcb();
            }

            if (!listClusters.data.length) {
                helpers.addResult(results, 0, 'No ECS clusters present', region);
                return rcb();
            }

            for (var clusterARN of listClusters.data) {
                var describeCluster = helpers.addSource(cache, source,
                    ['ecs', 'describeCluster', region, clusterARN]);
        
                if (!describeCluster || describeCluster.err ||!describeCluster.data ||
                    !describeCluster.data.clusters || !describeCluster.data.clusters.length) {
                    helpers.addResult(results, 3,
                        'Unable to describe ECS cluster: ' +helpers.addError(describeCluster), region, clusterARN);
                    continue;
                }

                const cluster = describeCluster.data.clusters[0];
                let containerInsightsEnabled = (cluster.settings && cluster.settings.length) ? cluster.settings.find(item => item.name == 'containerInsights' && item.value == 'enabled') : false;

                if (containerInsightsEnabled) {
                    helpers.addResult(results, 0,
                        'ECS cluster has container insights enabled', region, clusterARN);
                } else {
                    helpers.addResult(results, 2,
                        'ECS cluster does not have container insights enabled', region, clusterARN);
                }             
            }
            rcb();
        },
        function(){
            callback(null, results, source);
        });
    }
};
