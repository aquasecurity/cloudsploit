const {
    ElasticLoadBalancing
} = require('@aws-sdk/client-elastic-load-balancing');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var elb = new ElasticLoadBalancing(AWSConfig);

    async.eachLimit(collection.elb.describeLoadBalancers[AWSConfig.region].data, 15, function(lb, cb){
        collection.elb.describeTags[AWSConfig.region][lb.LoadBalancerName] = {};
        var params = {
            'LoadBalancerNames': [lb.LoadBalancerName]
        };

        helpers.makeCustomCollectorCall(elb, 'describeTags', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.elb.describeTags[AWSConfig.region][lb.LoadBalancerName].err = err;
            }

            if (data) collection.elb.describeTags[AWSConfig.region][lb.LoadBalancerName].data = data;
            cb();
        });
    }, function(){
        callback();
    });
};