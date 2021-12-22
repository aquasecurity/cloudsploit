var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Audit Logging Enabled',
    category: 'Logging',
    domain: 'Management and Governance',
    description: 'Ensures that default audit logging is enabled on the organization or project.',
    more_info: 'The default audit logs should be configured to log all admin activities and write and read access to data for all services. In addition, no exempted members should be added to the logs to ensure proper delivery of all audit logs.',
    link: 'https://cloud.google.com/logging/docs/audit/',
    recommended_action: 'Ensure that the default audit logs are enabled to log all admin activities and write and read access to data for all services.',
    apis: ['projects:getIamPolicy', 'organizations:list', 'organizations:getIamPolicy'],
    settings: {
        check_org_audit_logs: {
            name: 'Check Org Audit Logs',
            description: 'If set to true, check if audit logging is enabled on organization level. If enabled on organization level, ' +
                'return PASS result otherwise check for project audit logging',
            regex: '^(true|false)$',
            default: 'false'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();
        var config = {
            check_org_audit_logs: settings.check_org_audit_logs || this.settings.check_org_audit_logs.default
        };

        config.check_org_audit_logs = (config.check_org_audit_logs == 'true');
        var enabledOnOrg = false;

        if (config.check_org_audit_logs) {
            let getIamPolicy = helpers.addSource(cache, source,
                ['organizations', 'getIamPolicy', 'global']);
            
            if (!getIamPolicy) return callback(null, results, source);

            if (getIamPolicy.err || !getIamPolicy.data) {
                helpers.addResult(results, 3, 'Unable to query for IAM policies for org', 'global', null, null, getIamPolicy.err);
                return callback(null, results, source);
            }

            let iamPolicy = getIamPolicy.data[0];
            if (iamPolicy &&
                iamPolicy.auditConfigs) {
                let auditConfig = iamPolicy.auditConfigs.find(auditConfig => (auditConfig.service && auditConfig.service === 'allServices'));
                if (auditConfig &&
                    auditConfig.auditLogConfigs &&
                    auditConfig.auditLogConfigs.length) {

                    let auditLogConfigs = auditConfig.auditLogConfigs.filter(auditLogConfig => {
                        return (['ADMIN_READ', 'DATA_READ', 'DATA_WRITE'].indexOf(auditLogConfig.logType) > - 1);
                    });

                    let exemptedMembers = auditConfig.auditLogConfigs.filter(auditLogConfig => {
                        return (auditLogConfig.exemptedMembers && auditLogConfig.exemptedMembers.length);
                    });

                    if (auditLogConfigs.length == 3 && !exemptedMembers.length) {
                        enabledOnOrg = true;
                    }
                }
                if (!enabledOnOrg) {
                    let loggingEnabledServices = iamPolicy.auditConfigs.filter(config => {
                        return ((config.auditLogConfigs.filter(auditLogConfig => {
                            return (['ADMIN_READ', 'DATA_READ', 'DATA_WRITE'].indexOf(auditLogConfig.logType) > - 1);
                        }).length) == 3);
                    });
                    if (loggingEnabledServices && loggingEnabledServices.length >= 100) {
                        enabledOnOrg = true;
                    }
                }
                if (enabledOnOrg) {
                    helpers.addResult(results, 0, 'Audit logging is enabled on the organization', 'global');
                }
            }
        }
        if (enabledOnOrg) return callback(null, results, source);

        async.each(regions.projects, function(region, rcb){
            let iamPolicies = helpers.addSource(cache, source,
                ['projects', 'getIamPolicy', region]);

            if (!iamPolicies) return rcb();

            if (iamPolicies.err || !iamPolicies.data) {
                helpers.addResult(results, 3, 'Unable to query for IAM policies', region, null, null, iamPolicies.err);
                return rcb();
            }

            if (!iamPolicies.data.length) {
                helpers.addResult(results, 2, 'No IAM policies found.', region);
                return rcb();
            }

            var iamPolicy = iamPolicies.data[0];

            var foundLoggingConfig = false;
            let status, message;
            if (iamPolicy &&
                iamPolicy.auditConfigs) {
                let auditConfig = iamPolicy.auditConfigs.find(auditConfig => (auditConfig.service && auditConfig.service === 'allServices'));
                if (auditConfig &&
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
                        status = 2;
                        message = 'Audit logging is not properly configured on the project';
                    } else if (exemptedMembers.length) {
                        status = 2;
                        message = 'Default audit configuration has exempted members';
                    } else {
                        status = 0;
                        message = 'Audit logging is enabled on the project';
                    }
                }

                if (typeof status == 'undefined' || status > 0) {
                    let loggingEnabledServices = 0;
                    let projectExemptedMembers = false;

                    if (iamPolicy.auditConfigs && iamPolicy.auditConfigs.length) {
                        loggingEnabledServices = iamPolicy.auditConfigs.filter(config => {
                            return ((config.auditLogConfigs.filter(auditLogConfig => {
                                return (['ADMIN_READ', 'DATA_READ', 'DATA_WRITE'].indexOf(auditLogConfig.logType) > - 1);
                            }).length) == 3);
                        });

                        for (let config of iamPolicy.auditConfigs) {
                            if (config.auditLogConfigs && config.auditLogConfigs.length) {
                                for (let auditLogConfig of config.auditLogConfigs) {
                                    if (auditLogConfig.exemptedMembers && auditLogConfig.exemptedMembers.length) {
                                        projectExemptedMembers = true;
                                        break;
                                    }
                                }
                            }
                            if (projectExemptedMembers) break;
                        }
                    }

                    if (loggingEnabledServices && loggingEnabledServices.length >= 100 && !projectExemptedMembers) {
                        status = 0;
                        message = 'Audit logging is enabled on the project';
                    } else if (loggingEnabledServices && loggingEnabledServices.length && projectExemptedMembers) {
                        status = 2;
                        message = 'Audit logging has exempted members for some services in the project';
                    } else if (loggingEnabledServices && loggingEnabledServices.length) {
                        status = 2;
                        message = 'Audit logging is not properly configured on the project';
                    } else if (typeof status == 'undefined' && !message) {
                        status = 2;
                        message = 'Audit logging is not enabled on the project';
                    }
                }
                foundLoggingConfig = true;
                helpers.addResult(results, status, message, region);
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
