var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var elb = new AWS.ELB(AWSConfig);

    async.eachLimit(collection.elb.describeLoadBalancers[AWSConfig.region].data, 15, function(lb, cb){
        collection.elb.describeInstanceHealth[AWSConfig.region][lb.DNSName] = {};
        var params = {
            'LoadBalancerName':lb.LoadBalancerName
        };

        helpers.makeCustomCollectorCall(elb, 'describeInstanceHealth', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.elb.describeInstanceHealth[AWSConfig.region][lb.DNSName].err = err;
            }
            if (data) collection.elb.describeInstanceHealth[AWSConfig.region][lb.DNSName].data = data;
            cb();
        });
    }, function(){
        callback();
    });
};
