var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Security Lake VPC Flow Logs Source Enabled',
    category: 'Security Lake',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures that VPC Flow Logs is enabled as a log source in Amazon Security Lake.',
    more_info: 'Amazon Security Lake centralizes security data from AWS services into a data lake and normalizes it to the Open Cybersecurity Schema Framework (OCSF). ' +
        'Adding VPC Flow Logs as a source gives analysts and detection tooling visibility into network traffic in the VPCs of the account, ' +
        'which is needed to investigate lateral movement, data exfiltration and unusual traffic patterns.',
    link: 'https://docs.aws.amazon.com/security-lake/latest/userguide/internal-sources.html',
    recommended_action: 'Add VPC Flow Logs (VPC_FLOW) as a log source in Amazon Security Lake in every region that has a data lake.',
    apis: ['SecurityLake:listDataLakes', 'SecurityLake:listLogSources', 'STS:getCallerIdentity'],
    settings: {
        security_lake_required: {
            name: 'Security Lake Required',
            description: 'When set to true, return a failing result for regions where Security Lake is not enabled. ' +
                'When set to false, regions without a Security Lake data lake are not evaluated and pass.',
            regex: '^(true|false)$',
            default: 'false'
        }
    },
    realtime_triggers: ['securitylake:CreateAwsLogSource', 'securitylake:DeleteAwsLogSource',
        'securitylake:CreateDataLake', 'securitylake:DeleteDataLake'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var regions = helpers.regions(settings);
        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        var config = {
            securityLakeRequired: (settings.security_lake_required || this.settings.security_lake_required.default) === 'true'
        };

        async.each(regions.securitylake, function(region, rcb) {
            var listDataLakes = helpers.addSource(cache, source, ['securitylake', 'listDataLakes', region]);
            if (!listDataLakes) return rcb();

            if (listDataLakes.err || !listDataLakes.data) {
                helpers.addResult(results, 3,
                    'Unable to query Security Lake data lakes: ' + helpers.addError(listDataLakes), region);
                return rcb();
            }

            var dataLake = listDataLakes.data.find(function(lake) {
                return lake.region === region;
            });

            if (!dataLake) {
                if (config.securityLakeRequired) {
                    helpers.addResult(results, 2, 'Security Lake is not enabled', region);
                } else {
                    helpers.addResult(results, 0, 'Security Lake is not enabled in the region', region);
                }
                return rcb();
            }

            var resource = dataLake.dataLakeArn;

            if (dataLake.createStatus === 'FAILED') {
                helpers.addResult(results, 2, 'Security Lake data lake creation failed', region, resource);
                return rcb();
            }

            if (dataLake.createStatus && dataLake.createStatus !== 'COMPLETED') {
                helpers.addResult(results, 1,
                    'Security Lake data lake is not ready yet, status: ' + dataLake.createStatus, region, resource);
                return rcb();
            }

            var listLogSources = helpers.addSource(cache, source, ['securitylake', 'listLogSources', region]);
            if (!listLogSources) return rcb();

            if (listLogSources.err || !listLogSources.data) {
                helpers.addResult(results, 3,
                    'Unable to query Security Lake log sources: ' + helpers.addError(listLogSources), region, resource);
                return rcb();
            }

            // In a delegated administrator account the response also contains member accounts:
            // only look at the account that is being scanned (when it is known)
            var vpcFlowEnabled = listLogSources.data.some(function(entry) {
                if (accountId && entry.account && entry.account !== accountId) return false;
                if (entry.region && entry.region !== region) return false;

                return (entry.sources || []).some(function(logSource) {
                    return logSource.awsLogSource && logSource.awsLogSource.sourceName === 'VPC_FLOW';
                });
            });

            if (vpcFlowEnabled) {
                helpers.addResult(results, 0, 'VPC Flow Logs is enabled as a source in Security Lake', region, resource);
            } else {
                helpers.addResult(results, 2, 'VPC Flow Logs is not enabled as a source in Security Lake', region, resource);
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
