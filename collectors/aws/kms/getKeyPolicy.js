var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var kms = new AWS.KMS(AWSConfig);

    async.eachLimit(collection.kms.listKeys[AWSConfig.region].data, 15, function(key, cb){
        collection.kms.getKeyPolicy[AWSConfig.region][key.KeyId] = {};

        var params = {
            // The identifier of the CMK whose key policy you want to retrieve.
            // You can use the key ID or the Amazon Resource Name (ARN) of the CMK.
            KeyId: key.KeyId,
            // The name of the key policy to retrieve.
            PolicyName: 'default'
        };

        kms.getKeyPolicy(params, function(err, data) {
            if (err) {
                collection.kms.getKeyPolicy[AWSConfig.region][key.KeyId].err = err;
            }
            // convert the data to json object
            var policyData;
            try {
                policyData = JSON.parse(data.Policy);
            } catch(e) {
                policyData = null;
            }
            
            collection.kms.getKeyPolicy[AWSConfig.region][key.KeyId].data = policyData;
            cb();
        });
    }, function(){
        callback();
    });
};