var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var accessanalyzer = new AWS.AccessAnalyzer(AWSConfig);
    async.eachLimit(collection.accessanalyzer.listAnalyzers[AWSConfig.region].data, 15, function(analyzer, cb) {
        collection.accessanalyzer.listFindingsV2[AWSConfig.region][analyzer.arn] = {};
        var params = {
            analyzerArn: analyzer.arn
        };

        var paginating = false;
        var paginateCb = function(err, data) {
            if (err) collection.accessanalyzer.listFindingsV2[AWSConfig.region][analyzer.arn].err = err;

            if (!data) return cb();

            if (paginating && data.findings && data.findings.length &&
                collection.accessanalyzer.listFindingsV2[AWSConfig.region][analyzer.arn].data.findings &&
                collection.accessanalyzer.listFindingsV2[AWSConfig.region][analyzer.arn].data.findings.length) {
                collection.accessanalyzer.listFindingsV2[AWSConfig.region][analyzer.arn].data.findings = collection.accessanalyzer.listFindingsV2[AWSConfig.region][analyzer.arn].data.findings.concat(data.findings);
            } else {
                collection.accessanalyzer.listFindingsV2[AWSConfig.region][analyzer.arn].data = data;
            }

            if (data.nextToken && data.nextToken.length) {
                paginating = true;
                return execute(data.nextToken);
            }

            cb();
        };

        function execute(nextToken) { // eslint-disable-line no-inner-declarations
            var localParams = JSON.parse(JSON.stringify(params || {}));
            if (nextToken) localParams['nextToken'] = nextToken;
            if (nextToken) {
                helpers.makeCustomCollectorCall(accessanalyzer, 'listFindingsV2', localParams, retries, null, null, null, paginateCb);
            } else {
                helpers.makeCustomCollectorCall(accessanalyzer, 'listFindingsV2', params, retries, null, null, null, paginateCb);
            }
        }

        execute();
    }, function(){
        callback();
    });
};