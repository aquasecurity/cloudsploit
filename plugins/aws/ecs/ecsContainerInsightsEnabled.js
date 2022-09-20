var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Container Insights Enabled',
    category: 'ECS',
    domain: 'Containers',
    description:
      'Ensure that ECS clusters have CloudWatch Container Insights feature enabled.',
    more_info:
      'CloudWatch Container Insights provides monitoring and troubleshooting solution for containerized applications and microservices that collects, aggregates and summarizes resource utilization such as CPU, memory, disk, and network.',
    recommended_action: 'Enabled container insights feature for ECS clusters.',
    link: 'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/cloudwatch-container-insights.html',
    apis: ['ECS:listClusters', 'ECS:describeCluster'],

    run: function(cache, settings, callback){

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(
            regions.ecs,
            function(region, rcb){
                var listClusters = helpers.addSource(cache, source, [
                    'ecs',
                    'listClusters',
                    region
                ]);
                if (!listClusters) return rcb();

                if (listClusters.err || !listClusters.data) {
                    helpers.addResult(
                        results,
                        3,
                        'Unable to query for ECS clusters: ' +
              helpers.addError(listClusters),
                        region
                    );
                    return rcb();
                }

                if (listClusters.data.length === 0) {
                    helpers.addResult(results, 0, 'No ECS clusters present', region);
                    return rcb();
                }
     
                for (var c in listClusters.data) {
                    var clsuterARN = listClusters.data[c];
                    var describeCluster = helpers.addSource(cache, source, [
                        'ecs',
                        'describeCluster',
                        region,
                        clsuterARN
                    ]);
                    var arn = clsuterARN;
            
                    if (
                        !describeCluster ||
            describeCluster.err ||
            !describeCluster.data
                    ) {
                        helpers.addResult(
                            results,
                            3,
                            'Unable to describe ECS cluster: ' +
                                helpers.addError(describeCluster),
                            region,
                            arn
                        );
                        continue;
                    }

                    if (
                        describeCluster.data.clusters &&
                        describeCluster.data.clusters.length
                    ) {   
            
                        for ( var index in describeCluster.data.clusters) {
             
                            const cluster = describeCluster.data.clusters[index];
                            if (cluster.settings.length > 0){ 
                                for (var item of cluster.settings ){ 
                                    if (item.name === 'containerInsights' ){

                                        if ( item.value === 'enabled'){

                                            helpers.addResult(
                                                results,
                                                0,
                                                'ECS cluster container Insights is enabled',
                                                region,
                                                arn
                                            );
                                        } else {
                                            helpers.addResult(
                                                results,
                                                2,
                                                'ECS cluster container insights  not enabled',
                                                region,
                                                arn
                                            );
                                        }
                                    }

                                }
                            }
             
                        }            
                    } 
                }

                rcb();
            },
            function(){
                callback(null, results, source);
            }
        );
    }
};
