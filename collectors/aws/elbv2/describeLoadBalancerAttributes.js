var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var elb = new AWS.ELBv2(AWSConfig);

    async.eachLimit(collection.elbv2.describeLoadBalancers[AWSConfig.region].data, 15, function(lb, cb){
        collection.elbv2.describeLoadBalancerAttributes[AWSConfig.region][lb.DNSName] = {};
        var params = {
            'LoadBalancerArn':lb.LoadBalancerArn
        };
        elb.describeLoadBalancerAttributes(params, function(err, data) {
            if (err) {
                collection.elbv2.describeLoadBalancerAttributes[AWSConfig.region][lb.DNSName].err = err;
            }
            collection.elbv2.describeLoadBalancerAttributes[AWSConfig.region][lb.DNSName].data = data;
            cb();
        });

    }, function(){
        callback();
    });
};
