const {
    WAFV2
} = require('@aws-sdk/client-wafv2');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var wafv2 = new WAFV2(AWSConfig);

    async.eachLimit(collection.wafv2.listWebACLs[AWSConfig.region].data, 15, function(acl, cb){        
        var params = {
            'Name': acl.Name,
            'Id': acl.Id,
            'Scope': 'REGIONAL'
        };

        helpers.makeCustomCollectorCall(wafv2, 'getWebACL', params, retries, null, null, null, function(err, data) {
            collection.wafv2.getWebACL[AWSConfig.region][acl.ARN] = {};

            if (err) {
                collection.wafv2.getWebACL[AWSConfig.region][acl.ARN].err = err;
            } else {
                collection.wafv2.getWebACL[AWSConfig.region][acl.ARN].data = data;
            }
            cb();
        });
                
    }, function(){
        callback();
    });
};
