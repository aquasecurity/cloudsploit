var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElastiCache Reserved Cache Node Payment Pending',
    category: 'ElastiCache',
    domain: 'Databases',
    description: 'Ensure that any payment pending ElastiCache Reserved Cache Nodes available within your AWS account has been purchase successfully confirmed. ',
    more_info: 'When using ElastiCache Reserved Cache Nodes over standard On-Demand Cache Nodes savings are up to max they give when used in steady state, therefore in order to receive this benefit you need to make sure that all your ElastiCache reservation purchases have been fully successful.',
    link: 'https://aws.amazon.com/elasticache/reserved-cache-nodes/',
    recommended_action: 'Enable reserved cache nodes payment state for ElastiCache clusters',
    apis: ['ElastiCache:describeReservedCacheNodes'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.elasticache, function(region, rcb){
            var describeReservedCacheNodes = helpers.addSource(cache, source,
                ['elasticache', 'describeReservedCacheNodes', region]);

            if (!describeReservedCacheNodes) return rcb();

            if (describeReservedCacheNodes.err || !describeReservedCacheNodes.data) {
                helpers.addResult(results, 3,
                    'Unable to query for ElastiCache Reserved Cache Node: ' + helpers.addError(describeReservedCacheNodes), region);
                return rcb();
            }

            if (!describeReservedCacheNodes.data.length) {
                helpers.addResult(results, 0, 'No ElastiCache Reserved Cache Node found', region);
                return rcb();
            }
            
            for (var cluster of describeReservedCacheNodes.data) {
                if (!cluster.ReservationARN) continue;

                var resource = cluster.ReservationARN;

                if (cluster.State === 'payment-pending') {
                    helpers.addResult(results, 0,
                        'ElastiCache Reserved Cache Node have pending payment', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'ElastiCache Reserved Cache Node does not have pending payment', region, resource);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
