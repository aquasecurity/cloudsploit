// TODO: re-visit this one

var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var elb = new AWS.ELB(AWSConfig);

    // Gather list of policies from load balancers
    var policies = [];

    for (var i in collection.elb.describeLoadBalancers[AWSConfig.region].data) {
        var lb = collection.elb.describeLoadBalancers[AWSConfig.region].data[i];

        for (var j in lb.ListenerDescriptions) {
            var lsDescs = lb.ListenerDescriptions[j];

            if (lsDescs.Listener &&
                lsDescs.Listener.Protocol &&
                lsDescs.Listener.Protocol === 'HTTPS') {
                var elbPolicies = [];
                
                for (var k in lsDescs.PolicyNames) {
                    elbPolicies.push(lsDescs.PolicyNames[k]);
                }
                
                if (elbPolicies.length) {
                    var elbObj = {
                        LoadBalancerName: lb.LoadBalancerName,
                        DNSName: lb.DNSName,
                        PolicyNames: elbPolicies
                    };
                    policies.push(elbObj);
                }
            }
        }
    }

    if (!policies.length) return callback();

    async.eachLimit(policies, 15, function(policy, cb){
        collection.elb.describeLoadBalancerPolicies[AWSConfig.region][policy.DNSName] = {};

        let params = {
            LoadBalancerName: policy.LoadBalancerName,
            PolicyNames: policy.PolicyNames
        };

        helpers.makeCustomCollectorCall(elb, 'describeLoadBalancerPolicies', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.elb.describeLoadBalancerPolicies[AWSConfig.region][policy.DNSName].err = err;
            } else {
                collection.elb.describeLoadBalancerPolicies[AWSConfig.region][policy.DNSName].data = data;
            }

            cb();
        });
    }, function(){
        callback();
    });
};