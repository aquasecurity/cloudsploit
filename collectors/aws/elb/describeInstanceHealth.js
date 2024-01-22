const {
    ElasticLoadBalancing
} = require('@aws-sdk/client-elastic-load-balancing');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var elb = new ElasticLoadBalancing(AWSConfig);

    async.eachLimit(collection.elb.describeLoadBalancers[AWSConfig.region].data, 15, function(lb, cb){
        collection.elb.describeInstanceHealth[AWSConfig.region][lb.DNSName] = {};
        var params = {
            'LoadBalancerName':lb.LoadBalancerName
        };

        helpers.makeCustomCollectorCall(elb, 'describeInstanceHealth', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.elb.describeInstanceHealth[AWSConfig.region][lb.DNSName].err = err;
            }
            collection.elb.describeInstanceHealth[AWSConfig.region][lb.DNSName].data = data;
            cb();
        });
    }, function(){
        callback();
    });
};
