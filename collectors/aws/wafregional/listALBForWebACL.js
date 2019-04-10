var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
	var wafregional = new AWS.WAFRegional(AWSConfig);

	async.eachLimit(collection.wafregional.listWebACLs[AWSConfig.region].data, 15, function(webacl, cb){
        collection.wafregional.listALBForWebACL[AWSConfig.region][webacl.WebACLId] = {};

        var params = {
            WebACLId: webacl.WebACLId,
            ResourceType: 'APPLICATION_LOAD_BALANCER'
        };

        wafregional.listResourcesForWebACL(params, function(err, data) {
            if (err) {
                collection.wafregional.listALBForWebACL[AWSConfig.region][webacl.WebACLId].err = err;
            } else {
                collection.wafregional.listALBForWebACL[AWSConfig.region][webacl.WebACLId].data = data.ResourceArns;
            }
            cb();
        });
    }, function(){
        callback();
    });
};