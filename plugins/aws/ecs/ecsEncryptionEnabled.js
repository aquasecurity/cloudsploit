var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ECS Encryption Enabled',
    category: 'ECS',
    domain: 'Container',
    description: 'Ensure that ECS clusters have encryption feature enabled.',
    more_info: 'Encrypt the data between the local client and the container.',
    recommended_action: 'Enabled container encryption feature for ECS clusters by using aws cli and run the command.',
    link: 'https://docs.aws.amazon.com/AmazonECS/latest/bestpracticesguide/security-network.html',
    apis: ['ECS:listClusters','ECS:describeCluster'],

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
                        'Unable to describe ECS cluster: ' + helpers.addError(describeCluster), region, clusterARN);
                    continue;
                }

                const cluster = describeCluster.data.clusters[0];
                let containerEncryptionEnabled = (cluster.configuration?.executeCommandConfiguration?.KmsKeyId) ? true : false;
                if (containerEncryptionEnabled) {
                    helpers.addResult(results, 0,
                        'ECS cluster has ecryption enabled', region, clusterARN);
                } else {
                    helpers.addResult(results, 2,
                        'ECS cluster does not have ecryption enabled', region, clusterARN);
                }             
            }
            rcb();
        },
        function(){
            callback(null, results, source);
        });
    }
};