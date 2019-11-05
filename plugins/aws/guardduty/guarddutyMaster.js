var async = require('async');
var helpers = require('../../../helpers/aws');

var defaultKmsKey = 'alias/aws/firehose';

module.exports = {
    title: 'GuardDuty Master Account',
    category: 'GuardDuty',
    description: 'Ensures GuardDuty master account is correct',
    link: 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_accounts.html#guardduty_master',
    apis: ['GuardDuty:getMasterAccount', 'GuardDuty:listDetectors'],
    settings: {
        guardduty_master_account: {
            name: 'GuardDuty Master Account ID',
            description: 'Return a failing result when the GuardDuty master account is not this account. Leave blank to allow all.',
            regex: '^.*$',
            default: '',
        },
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var guarddutyMasterAccount = settings.guardduty_master_account || this.settings.guardduty_master_account.default;
        if (guarddutyMasterAccount === '') {
            return callback(null, results, source);
        }

        async.each(regions.guardduty, function(region, rcb) {
            var listDetectors = helpers.addSource(cache, source, ['guardduty', 'listDetectors', region]);
            if (!listDetectors) return rcb();
            if (listDetectors.err) {
                helpers.addResult(results, 3, 'Unable to query GuardDuty', region);
            } else if (listDetectors.data.length > 0) {
                for (let detectorId of listDetectors.data) {
                    var getMasterAccount = helpers.addSource(cache, source, ['guardduty', 'getMasterAccount', region, detectorId]);
                    if (!getMasterAccount) return rcb();

                    if (!getMasterAccount.data.Master) {
                        helpers.addResult(results, 2, `GuardDuty master account is not configured`, region);
                    } else if (getMasterAccount.data.Master.AccountId === guarddutyMasterAccount) {
                        helpers.addResult(results, 0, `GuardDuty master account is ${guarddutyMasterAccount}`, region);
                    } else {
                        helpers.addResult(results, 2, `GuardDuty master account is not ${guarddutyMasterAccount}`, region);
                    }
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
