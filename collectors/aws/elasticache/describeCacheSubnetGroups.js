var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var elasticache = new AWS.ElastiCache(AWSConfig);

    async.eachLimit(collection.elasticache.describeCacheClusters[AWSConfig.region].data, 15, function(cluster, cb){
        collection.elasticache.describeCacheSubnetGroups[AWSConfig.region][cluster.CacheSubnetGroupName] = {};
        var params = {
            CacheSubnetGroupName: cluster.CacheSubnetGroupName
        };

        helpers.makeCustomCollectorCall(elasticache, 'describeCacheSubnetGroups', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.elasticache.describeCacheSubnetGroups[AWSConfig.region][cluster.CacheSubnetGroupName].err = err;
            }
            collection.elasticache.describeCacheSubnetGroups[AWSConfig.region][cluster.CacheSubnetGroupName].data = data;
            cb();
        });
    }, function(){
        callback();
    });
};
