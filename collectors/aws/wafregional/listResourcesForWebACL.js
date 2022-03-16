var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var wafregional = new AWS.WAFRegional(AWSConfig);
    async.eachLimit(collection.wafregional.listWebACLs[AWSConfig.region].data, 15, function(dep, depCb){
        async.each(['APPLICATION_LOAD_BALANCER', 'API_GATEWAY'], function(thisCheck, tcCb){
            if (!collection['wafregional']['listResourcesForWebACL'][AWSConfig.region][dep['WebACLId']]) collection['wafregional']['listResourcesForWebACL'][AWSConfig.region][dep['WebACLId']] = {};

            var filter = {};
            filter['WebACLId'] = dep['WebACLId'];
            filter['ResourceType'] = thisCheck;
            helpers.makeCustomCollectorCall(wafregional, 'listResourcesForWebACL', filter, retries, null, null, null, function(err, data) {
                if (err) {
                    collection['wafregional']['listResourcesForWebACL'][AWSConfig.region][dep['WebACLId']].err = err;
                    return tcCb();
                } else {
                    if (!collection['wafregional']['listResourcesForWebACL'][AWSConfig.region][dep['WebACLId']].data) {
                        collection['wafregional']['listResourcesForWebACL'][AWSConfig.region][dep['WebACLId']].data = data;
                    } else if (collection['wafregional']['listResourcesForWebACL'][AWSConfig.region][dep['WebACLId']].data &&
                        collection['wafregional']['listResourcesForWebACL'][AWSConfig.region][dep['WebACLId']].data.ResourceWebACLIds &&
                        collection['wafregional']['listResourcesForWebACL'][AWSConfig.region][dep['WebACLId']].data.ResourceWebACLIds.length &&
                        data.ResourceWebACLIds && data.ResourceWebACLIds.length) {
                        collection['wafregional']['listResourcesForWebACL'][AWSConfig.region][dep['WebACLId']].data.ResourceWebACLIds = collection['wafregional']['listResourcesForWebACL'][AWSConfig.region][dep['WebACLId']].data.ResourceWebACLIds.concat(data.ResourceWebACLIds);
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
