const {
    ElasticLoadBalancingV2
} = require('@aws-sdk/client-elastic-load-balancing-v2');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var elb = new ElasticLoadBalancingV2(AWSConfig);

    async.eachLimit(collection.elbv2.describeLoadBalancers[AWSConfig.region].data, 15, function(lb, cb){
        collection.elbv2.describeListeners[AWSConfig.region][lb.DNSName] = {};
        var params = {
            'LoadBalancerArn':lb.LoadBalancerArn
        };

        helpers.makeCustomCollectorCall(elb, 'describeListeners', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.elbv2.describeListeners[AWSConfig.region][lb.DNSName].err = err;
            }
            collection.elbv2.describeListeners[AWSConfig.region][lb.DNSName].data = data;
            cb();
        });

    }, function(){
        callback();
    });
};
