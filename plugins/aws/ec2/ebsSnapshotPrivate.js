var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EBS Volume Snapshot Public',
    category: 'EC2',
    description: 'Ensures EBS volume snapshots are private',
    more_info: 'EBS volumes often contain sensitive data from running EC2 instances and should be set to private so they cannot be accidentally shared with other accounts.',
    recommended_action: 'Ensure that each EBS snapshot has its permissions set to private.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-modifying-snapshot-permissions.html',
    apis: ['Support:describeTrustedAdvisorChecks', 'Support:describeTrustedAdvisorCheckResult'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.support, function(region, rcb) {
            var describeTrustedAdvisorChecks = helpers.addSource(cache, source, ['support', 'describeTrustedAdvisorChecks', region]);

            if (!describeTrustedAdvisorChecks || describeTrustedAdvisorChecks.err || !describeTrustedAdvisorChecks.data) {
                var errMsg = helpers.addError(describeTrustedAdvisorChecks);
                if (errMsg === 'AWS Premium Support Subscription is required to use this service.') {
                    errMsg = 'Please activate AWS Premium Support';
                }
                helpers.addResult(results, 3, 'Unable to query for Trusted Advisor checks: ' + errMsg);
                return rcb();
            }

            var checkName = 'Amazon EBS Public Snapshots';
            async.each(describeTrustedAdvisorChecks.data, function(check, cb) {
                if (check.name !== checkName) {
                    return cb();
                }

                var describeTrustedAdvisorCheckResult = helpers.addSource(cache, source, ['support', 'describeTrustedAdvisorCheckResult', region, check.id]);

                if (!describeTrustedAdvisorCheckResult || describeTrustedAdvisorCheckResult.err || !describeTrustedAdvisorCheckResult.data) {
                    helpers.addResult(results, 3, `Unable to query for Trusted Advisor check: "${checkName}" ${helpers.addError(describeTrustedAdvisorCheckResult)}`);
                    return cb(null, results, source);
                }

                if (describeTrustedAdvisorCheckResult.data.result.status === 'ok') {
                    helpers.addResult(results, 0, 'No public EBS Snapshots');
                    return cb(null, results, source);
                }

                var snapshotIDIndex = check.metadata.indexOf('Snapshot ID');
                describeTrustedAdvisorCheckResult.data.result.flaggedResources.forEach(function(resource) {
                    helpers.addResult(results, 2, 'EBS Snapshot is public', 'global', resource[snapshotIDIndex]);
                });
                cb(null, results, source);
            }, rcb);
        }, function() {
            callback(null, results, source);
        });
    }
};
