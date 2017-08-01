var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var elb = new AWS.ELB(AWSConfig);

    async.eachLimit(collection.elb.describeLoadBalancers[AWSConfig.region].data, 15, function(lb, cb){        
        collection.elb.describeLoadBalancerAttributes[AWSConfig.region][lb.LoadBalancerName] = {};
        var params = {
            'LoadBalancerName':lb.LoadBalancerName
        }
        elb.describeLoadBalancerAttributes(params, function(err, data) {
            if (err) {
                collection.elb.describeLoadBalancerAttributes[AWSConfig.region][lb.LoadBalancerName].err = err;
            }
            collection.elb.describeLoadBalancerAttributes[AWSConfig.region][lb.LoadBalancerName].data = data;
            cb();
        });
                
    }, function(){
        callback();
    });
};
