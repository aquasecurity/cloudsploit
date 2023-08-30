var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var inspector = new AWS.Inspector(AWSConfig);

    async.eachLimit(collection.inspector.listAssessmentTemplates[AWSConfig.region].data, 5, function(templateArn, cb) {
        collection.inspector.listAssessmentRuns[AWSConfig.region][templateArn] = {};
        
        var params = {
            assessmentTemplateArns: [templateArn]
        };

        helpers.makeCustomCollectorCall(inspector, 'listAssessmentRuns', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.inspector.listAssessmentRuns[AWSConfig.region].err = err;
            }

            collection.inspector.listAssessmentRuns[AWSConfig.region][templateArn].data = data;

            cb();
        });
    }, function() {
        callback();
    });
};
