var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, settings, scanAWSConfig, callback) {
    var ssm = new AWS.SSM(AWSConfig);

    async.eachLimit(collection.ssm.listDocuments[AWSConfig.region].data, 10, function(doc, cb){
        collection.ssm.describeDocumentPermission[AWSConfig.region][doc.Name] = {};

        var paginating = false;
        var paginateCb = function(err, data) {
            if (err) {
                collection.ssm.describeDocumentPermission[AWSConfig.region][doc.Name].err = err;
            } else if (data) {
                var existing = collection.ssm.describeDocumentPermission[AWSConfig.region][doc.Name].data;
                if (paginating && existing) {
                    existing.AccountIds = (existing.AccountIds || []).concat(data.AccountIds || []);
                    existing.AccountSharingInfoList = (existing.AccountSharingInfoList || []).concat(data.AccountSharingInfoList || []);
                    delete existing.NextToken;
                } else {
                    collection.ssm.describeDocumentPermission[AWSConfig.region][doc.Name].data = data;
                }

                if (data.NextToken && data.NextToken.length) {
                    paginating = true;
                    return execute(data.NextToken);
                }
            }

            cb();
        };

        function execute(nextToken) {
            var params = {
                Name: doc.Name,
                PermissionType: 'Share'
            };
            if (nextToken) params.NextToken = nextToken;

            helpers.makeCustomCollectorCall(ssm, 'describeDocumentPermission', params, retries, null, null, null, settings, scanAWSConfig, AWSConfig, paginateCb);
        }

        execute();
    }, function(){
        callback();
    });
};
