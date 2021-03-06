var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Audit Logging Enabled',
    category: 'Logging',
    description: 'Ensures that default audit logging is enabled on the project.',
        more_info: 'The default audit logs should be configured to log all admin activities and write and read access to data for all services. In addition, no exempted members should be added to the logs to ensure proper delivery of all audit logs.',
    link: 'https://cloud.google.com/logging/docs/audit/',
    recommended_action: 'Ensure that the default audit logs are enabled to log all admin activities and write and read access to data for all services.',
    apis: ['projects:getIamPolicy'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.projects, function(region, rcb){
            let iamPolicies = helpers.addSource(cache, source,
                ['projects', 'getIamPolicy', region]);

            if (!iamPolicies) return rcb();

            if (iamPolicies.err || !iamPolicies.data) {
                helpers.addResult(results, 3, 'Unable to query for IAM policies: ' + helpers.addError(iamPolicies), region);
                return rcb();
            }

            if (!iamPolicies.data.length) {
                helpers.addResult(results, 2, 'No IAM policies found.', region);
                return rcb();
            }

            var iamPolicy = iamPolicies.data[0];
            var foundLoggingConfig = false;
            if (iamPolicy &&
                iamPolicy.auditConfigs) {
                iamPolicy.auditConfigs.forEach(auditConfig => {
                    if (foundLoggingConfig) return;
                    if (auditConfig.service &&
                        auditConfig.service === "allServices" &&
                        auditConfig.auditLogConfigs &&
                        auditConfig.auditLogConfigs.length) {

                        var auditLogConfigs = auditConfig.auditLogConfigs.filter(auditLogConfig => {
                            return (['ADMIN_READ', 'DATA_READ', 'DATA_WRITE'].indexOf(auditLogConfig.logType) > - 1);
                        });

                        var exemptedMembers = auditConfig.auditLogConfigs.filter(auditLogConfig => {
                            return (auditLogConfig.exemptedMembers && auditLogConfig.exemptedMembers.length);
                        });

                        foundLoggingConfig = true;
                        if (auditLogConfigs.length < 3) {
                            helpers.addResult(results, 2, 'Audit logging is not properly configured on the project', region);
                        } else if (exemptedMembers.length) {
                            helpers.addResult(results, 2, 'Default audit configuration has exempted members', region);
                        } else {
                            helpers.addResult(results, 0, 'Audit logging is enabled on the project', region);
                        }
                    }
                });
            }
            if (!foundLoggingConfig) {
                helpers.addResult(results, 2, 'Audit logging is not enabled on the project', region);
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
