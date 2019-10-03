var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Log Retention Period',
    category: 'Audit',
    description: 'Ensure that the Audit Log Retention Period is configured correctly.',
    more_info: 'Audit logs should be kept for as long as internal compliance requires. If no requirements exist, best practices suggest a minimum of 365 days.',
    recommended_action: '1. Enter the Tenancy Details page in the Administration blade. 2. Select Edit Audit Retention Period at the top of the page. 3. Set the Audit Retention Period in days.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Audit/Tasks/settingretentionperiod.htm',
    apis: ['configuration:get'],
    settings: {
        audit_log_retention_days: {
            name: 'Audit Log Retention in Days',
            description: 'Return a failing result when Audit Logs are not configured to retain data for a specific amount of time',
            regex: '^(365|[1-9][1-9][0-9]?)$',
            default: 365
        },
    },

    run: function(cache, settings, callback) {
        var config = {
            audit_log_retention_days: settings.audit_log_retention_days || this.settings.audit_log_retention_days.default,
        };

        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.configuration, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var configurations = helpers.addSource(cache, source,
                    ['configuration', 'get', region]);

                if (!configurations) return rcb();

                if ((configurations.err && configurations.err.length) || !configurations.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for audit configurations: ' + helpers.addError(configurations), region);
                    return rcb();
                };

                if (!Object.keys(configurations.data).length) {
                    helpers.addResult(results, 0, 'No audit configurations present', region);
                    return rcb();
                };

                var configuration = configurations.data;
                if (configuration.retentionPeriodDays &&
                    configuration.retentionPeriodDays < config.audit_log_retention_days) {
                    helpers.addResult(results, 2,
                        `Audit configuration period is ${configuration.retentionPeriodDays} days`, region);
                    return rcb();
                } else {
                    helpers.addResult(results, 0,
                        `Audit configuration period is ${configuration.retentionPeriodDays} days`, region);
                    return rcb();
                }
            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};