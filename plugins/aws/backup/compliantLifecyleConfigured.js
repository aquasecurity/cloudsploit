var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AWS Backup Compliant Lifecycle Configured',
    category: 'Backup',
    domain: 'Storage',
    description: 'Ensure that a compliant lifecycle configuration is enabled for your Amazon Backup plans in order to meet compliance requirements when it comes to security and cost optimization.',
    more_info: 'The AWS Backup lifecycle configuration contains an array of transition objects specifying how long in days before a recovery point transitions to cold storage or is deleted.',
    recommended_action: 'Enable compliant lifecycle configuration for your Amazon Backup plans',
    link: 'https://docs.aws.amazon.com/aws-backup/latest/devguide/API_Lifecycle.html',
    apis: ['Backup:listBackupPlans', 'Backup:getBackupPlan'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.backup, function(region, rcb) {
            var listBackupPlans = helpers.addSource(cache, source,
                ['backup', 'listBackupPlans', region]);

            if (!listBackupPlans) return rcb();

            if (listBackupPlans.err || !listBackupPlans.data) {
                helpers.addResult(results, 3,
                    'Unable to list Backup plans: ' + helpers.addError(listBackupPlans), region);
                return rcb();
            }

            if (!listBackupPlans.data.length) {
                helpers.addResult(results, 0, 'No Backup plans found', region);
                return rcb();
            }

            for (let plan of listBackupPlans.data) {
                if (!plan.BackupPlanArn) continue;

                var resource = plan.BackupPlanArn;
                var getBackupPlan = helpers.addSource(cache, source,
                    ['backup', 'getBackupPlan', region, plan.BackupPlanId]);

                if (!getBackupPlan || getBackupPlan.err || !getBackupPlan.data) {
                    helpers.addResult(results, 3,
                        `Unable to get Backup plan description: ${helpers.addError(getBackupPlan)}`,
                        region, resource);
                }

                if (!getBackupPlan.data.BackupPlan ||
                    !getBackupPlan.data.BackupPlan.Rules) {
                    helpers.addResult(results, 2,
                        'No lifecycle configuration rules found for Backup plan', region, resource);
                }
                
                let found = getBackupPlan.data.BackupPlan.Rules.find(rule => rule.Lifecycle.DeleteAfterDays && rule.Lifecycle.MoveToColdStorageAfterDays);
                if (found) {
                    helpers.addResult(results, 0,
                        'Backup plan has lifecycle configuration enabled', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Backup plan does not have lifecycle configuration enabled', region, resource);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};