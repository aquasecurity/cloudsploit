var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElastiCache Reserved Cache Node Lease Expiration',
    category: 'ElastiCache',
    domain: 'Databases',
    description: 'Ensure that your AWS ElastiCache Reserved Cache Nodes are renewed before expiration in order to get a significant discount.',
    more_info: 'Reserved Cache Nodes can optimize your Amazon ElastiCache costs based on your expected usage. Since RCNs are not renewed automatically, purchasing another reserved ElastiCache nodes before expiration will guarantee their billing at a discounted hourly rate.',
    link: 'https://aws.amazon.com/elasticache/reserved-cache-nodes/',
    recommended_action: 'Enable ElastiCache reserved cache nodes expiration days alert',
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
                helpers.addResult(results, 0, 'No ElastiCache reserved cache nodes found', region);
                return rcb();
            }

            for (var cluster of describeReservedCacheNodes.data) {
                if (!cluster.ReservationARN) continue;

                var resource = cluster.ReservationARN;

                let start = cluster.StartTime;
                let duration = cluster.Duration;

                if (duration == 1 || duration == 3){
                    duration = duration * 31536000;
                }
                
                let expiry = Math.floor(new Date(start)) + (duration * 1000);
                let expirationDays = Math.round((new Date(expiry).getTime() - new Date().getTime())/(24*60*60*1000));

                if (expirationDays >= 30) {
                    helpers.addResult(results, 0,
                        'ElastiCache reserved cache node lease expires in ' + expirationDays + ' days', region, resource);
                } else if (expirationDays > 0 ) {
                    helpers.addResult(results, 2,
                        'ElastiCache reserved cache node lease expires in ' + expirationDays + ' days', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'ElastiCache reserved cache node lease has expired', region, resource);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};