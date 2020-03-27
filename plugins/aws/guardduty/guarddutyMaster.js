var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'GuardDuty Master Account',
    category: 'GuardDuty',
    description: 'Ensures GuardDuty master account is correct',
    more_info: 'Organizations with large numbers of AWS accounts should configure GuardDuty findings from all member accounts to be sent to a consistent master account.',
    link: 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_accounts.html#guardduty_master',
    recommended_action: 'Configure the member account to send GuardDuty findings to a known master account.',
    apis: ['GuardDuty:getMasterAccount', 'GuardDuty:listDetectors', 'STS:getCallerIdentity'],
    settings: {
        guardduty_master_account: {
            name: 'GuardDuty Master Account ID',
            description: 'Return a failing result when the GuardDuty master account is not this account. Leave blank to allow all.',
            regex: '^([0-9]{12}|[0-9]{0})$',
            default: '',
        },
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        var regions = helpers.regions(settings);

        var guarddutyMasterAccount = settings.guardduty_master_account || this.settings.guardduty_master_account.default;

        async.each(regions.guardduty, function(region, rcb) {
            var listDetectors = helpers.addSource(cache, source, ['guardduty', 'listDetectors', region]);
            if (!listDetectors) return rcb();
            if (listDetectors.err || !listDetectors.data) {
                helpers.addResult(results, 3,
                    'Unable to list guardduty detectors: ' + helpers.addError(listDetectors), region);
                return rcb();
            } else if (listDetectors.data.length > 0) {
                for (let detectorId of listDetectors.data) {
                    var getMasterAccount = helpers.addSource(cache, source, ['guardduty', 'getMasterAccount', region, detectorId]);

                    var arn = 'arn:' + awsOrGov + ':guardduty:' + region + ':' + accountId + ':detector/' + detectorId;
                    if (!getMasterAccount || !getMasterAccount.data.Master) {
                        helpers.addResult(results, 2, `GuardDuty master account is not configured`, region, arn);
                    } else {
                        if (getMasterAccount.data.Master.RelationshipStatus !== 'Enabled') {
                            helpers.addResult(results, 2, 'GuardDuty master account not enabled', region, arn);
                        } else {
                            if (guarddutyMasterAccount === '') {
                                helpers.addResult(results, 0, 'GuardDuty has master account configured', region, arn);
                            } else if (getMasterAccount.data.Master.AccountId === guarddutyMasterAccount) {
                                helpers.addResult(results, 0, `GuardDuty master account is account ${guarddutyMasterAccount}`, region, arn);
                            } else {
                                helpers.addResult(results, 2, `GuardDuty master account is not account ${guarddutyMasterAccount}`, region, arn);
                            }
                        }
                    }
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
