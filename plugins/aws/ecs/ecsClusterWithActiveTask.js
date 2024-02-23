var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ECS Cluster Service Active Tasks',
    category: 'ECS',
    domain: 'Containers',
    severity: 'Medium',
    description: 'Ensure ECS clusters have services with running tasks.',
    more_info: 'A task is the instantiation of a task definition within a cluster. Amazon ECS service instantiates and maintains the specified number of tasks simultaneously in a cluster. As a best practice, ensure you always have running tasks in a cluster.',
    recommended_action: 'Modify Cluster services and add tasks',
    link: 'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs_services.html',
    apis: ['ECS:listClusters', 'ECS:describeCluster'],
    realtime_triggers: ['ecs:CreateCluster', 'ecs:RunTask', 'ecs:StopTask', 'ecs:DeleteCluster'],

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
                
                if (!cluster) continue;

                if (cluster.activeServicesCount && cluster.activeServicesCount > 0 && 
                cluster.runningTasksCount && cluster.runningTasksCount > 0) {
                    helpers.addResult(results, 0,
                        'ECS cluster has service with running tasks', region, clusterARN);
                } else {
                    helpers.addResult(results, 2,
                        'ECS cluster does not have service with running tasks', region, clusterARN);
                }             
            }
            rcb();
        },
        function(){
            callback(null, results, source);
        });
    }
};
