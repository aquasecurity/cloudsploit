var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var wafv2 = new AWS.WAFV2(AWSConfig);
    async.eachLimit(collection.wafv2.listWebACLs[AWSConfig.region].data, 15, function(dep, depCb){
        async.each(['APPLICATION_LOAD_BALANCER', 'API_GATEWAY'], function(thisCheck, tcCb){
            if (!collection['wafv2']['listResourcesForWebACL'][AWSConfig.region][dep['ARN']]) collection['wafv2']['listResourcesForWebACL'][AWSConfig.region][dep['ARN']] = {};

            var filter = {};
            filter['WebACLArn'] = dep['ARN'];
            filter['ResourceType'] = thisCheck;
            helpers.makeCustomCollectorCall(wafv2, 'listResourcesForWebACL', filter, retries, null, null, null, function(err, data) {
                if (err) {
                    collection['wafv2']['listResourcesForWebACL'][AWSConfig.region][dep['ARN']].err = err;
                    return tcCb();
                } else {
                    if (!collection['wafv2']['listResourcesForWebACL'][AWSConfig.region][dep['ARN']].data) {
                        collection['wafv2']['listResourcesForWebACL'][AWSConfig.region][dep['ARN']].data = data;
                    } else if (collection['wafv2']['listResourcesForWebACL'][AWSConfig.region][dep['ARN']].data &&
                        collection['wafv2']['listResourcesForWebACL'][AWSConfig.region][dep['ARN']].data.ResourceArns &&
                        collection['wafv2']['listResourcesForWebACL'][AWSConfig.region][dep['ARN']].data.ResourceArns.length &&
                        data.ResourceArns && data.ResourceArns.length) {
                        collection['wafv2']['listResourcesForWebACL'][AWSConfig.region][dep['ARN']].data.ResourceArns = collection['wafv2']['listResourcesForWebACL'][AWSConfig.region][dep['ARN']].data.ResourceArns.concat(data.ResourceArns);
                    }

                    return tcCb();
                }
            });
        }, function() {
            setTimeout(function() {
                depCb();
            }, 600);
        });
    }, function(){
        callback();
    });
};
