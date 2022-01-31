var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var kms = new AWS.KMS(AWSConfig);
    async.eachLimit(collection.kms.listKeys[AWSConfig.region].data, 15, function(key, cb) {
        collection.kms.listGrants[AWSConfig.region][key.KeyId] = {};
        var params = {
            KeyId: key.KeyId
        };

        var paginating = false;
        var paginateCb = function(err, data) {
            if (err) collection.kms.listGrants[AWSConfig.region][key.KeyId].err = err;

            if (!data) return cb();

            if (paginating && data.Grants && data.Grants.length &&
                collection.kms.listGrants[AWSConfig.region][key.KeyId].data.Grants &&
                collection.kms.listGrants[AWSConfig.region][key.KeyId].data.Grants.length) {
                collection.kms.listGrants[AWSConfig.region][key.KeyId].data.Grants = collection.kms.listGrants[AWSConfig.region][key.KeyId].data.Grants.concat(data.Grants);
            } else {
                collection.kms.listGrants[AWSConfig.region][key.KeyId].data = data;
            }

            if (data.NextMarker && data.NextMarker.length) {
                paginating = true;
                return execute(data.NextMarker);
            }

            cb();
        };

        function execute(marker) { // eslint-disable-line no-inner-declarations
            var localParams = JSON.parse(JSON.stringify(params || {}));
            if (marker) localParams['Marker'] = marker;
            if (marker) {
                helpers.makeCustomCollectorCall(kms, 'listGrants', localParams, retries, null, null, null, paginateCb);
            } else {
                helpers.makeCustomCollectorCall(kms, 'listGrants', params, retries, null, null, null, paginateCb);
            }
        }

        execute();
    }, function(){
        callback();
    });
};

