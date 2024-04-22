var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ECS Cluster Active Services',
    category: 'ECS',
    domain: 'Containers',
    severity: 'Medium',
    description: 'Ensure that AWS ECS clusters have active services.',
    more_info: 'Amazon ECS service allows you to run and maintain a specified number of instances of a task definition simultaneously in an Amazon ECS cluster. It is recommended to have clusters with the active services to avoid any container attack surface.',
    recommended_action: 'Modify Cluster and create new service.',
    link: 'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs_services.html',
    apis: ['ECS:listClusters', 'ECS:describeCluster'],
    realtime_triggers: ['ecs:CreateCluster', 'ecs:CreateService', 'ecs:UpdateService', 'ecs:DeleteService', 'ecs:DeleteCluster'],

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

                if (cluster.activeServicesCount && cluster.activeServicesCount > 0) {
                    helpers.addResult(results, 0,
                        'ECS cluster has active services', region, clusterARN);
                } else {
                    helpers.addResult(results, 2,
                        'ECS cluster does not have active services', region, clusterARN);
                }             
            }
            rcb();
        },
        function(){
            callback(null, results, source);
        });
    }
};
