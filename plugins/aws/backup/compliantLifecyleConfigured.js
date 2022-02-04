var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Backup Vault Encrypted',
    category: 'Backup',
    domain: 'Storage',
    description: 'Ensure that a compliant lifecycle configuration is enabled for your Amazon Backup plans in order to meet compliance requirements when it comes to security and cost optimization. ',
    more_info: 'The AWS Backup lifecycle configuration contains an array of Transition objects specifying how long in days before a recovery point transitions to cold storage or is deleted.'+ 
        'DeleteAfterDays specifies the number of days after creation that a recovery point is deleted. MoveToColdStorageAfterDays Specifies the number of days after creation that a recovery point is moved to cold storage.',
    recommended_action: 'Enable compliant lifecycle configuration for your Amazon Backup plans in order to meet compliance requirements',
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
                    'Unable to query Backup plans: ' + helpers.addError(listBackupPlans), region);
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

                if (getBackupPlan.data.BackupPlan &&
                getBackupPlan.data.BackupPlan.Rules[0] &&
                getBackupPlan.data.BackupPlan.Rules[0].Lifecycle &&
                getBackupPlan.data.BackupPlan.Rules[0].Lifecycle.DeleteAfterDays == null &&
                getBackupPlan.data.BackupPlan.Rules[0].Lifecycle.MoveToColdStorageAfterDays == null) {
                    helpers.addResult(results, 2,
                        'No lifecycle configuration enabled for the selected Amazon Backup plan', region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'Lifecycle configuration enabled for the selected Amazon Backup plan', region, resource);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};