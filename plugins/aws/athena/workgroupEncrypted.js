var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Workgroup Encrypted',
    category: 'Athena',
    description: 'Ensures Athena workgroups are configured to encrypt all data at rest.',
    more_info: 'Athena workgroups support full server-side encryption for all data at rest which should be enabled.',
    link: 'https://docs.aws.amazon.com/athena/latest/ug/encryption.html',
    recommended_action: 'Enable encryption at rest for all Athena workgroups.',
    apis: ['Athena:listWorkGroups', 'Athena:getWorkGroup', 'STS:getCallerIdentity'],
    remediation_description: 'Encryption for the affected workgroups will be enabled.',
    remediation_min_version: '202011182332',
    apis_remediate: ['Athena:listWorkGroups', 'Athena:getWorkGroup', 'STS:getCallerIdentity'],
    actions: {
        remediate: ['Athena:updateWorkGroup'],
        rollback: ['Athena:updateWorkGroup']
    },
    permissions: {
        remediate: ['athena:UpdateWorkGroup'],
        rollback: ['athena:UpdateWorkGroup']
    },
    realtime_triggers: ['athena:CreateWorkGroup', 'athena:UpdateWorkGroup'],
    remediation_inputs: {
        encryptionOption: {
            name: '(Mandatory) Encryption method',
            description: 'SSE_S3 | SSE_KMS | CSE_KMS',
            regex: '^(SSE_S3|SSE_KMS|CSE_KMS)$',
            required: true
        },
        kmsKeyIdforWg: {
            name: '(Optional)KMS Key ID',
            description: 'The KMS Key ID used for encryption if encryption option is SSE_KMS or CSE_KMS',
            regex: '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$',
            required: false
        }
    },
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.athena, function(region, rcb){
            var listWorkGroups = helpers.addSource(cache, source,
                ['athena', 'listWorkGroups', region]);

            if (!listWorkGroups) return rcb();

            if (listWorkGroups.err || !listWorkGroups.data) {
                helpers.addResult(results, 3,
                    'Unable to list Athena workgroups: ' + helpers.addError(listWorkGroups), region);
                return rcb();
            }

            if (!listWorkGroups.data.length) {
                helpers.addResult(results, 0, 'No Athena workgroups found', region);
                return rcb();
            }

            // Loop through certificates
            listWorkGroups.data.forEach(function(wg){
                var getWorkGroup = helpers.addSource(cache, source,
                    ['athena', 'getWorkGroup', region, wg.Name]);

                // arn:aws:athena:region:account-id:workgroup/workgroup-name
                var arn = 'arn:aws:athena:' + region + ':' + accountId + ':workgroup/' + wg.Name;

                if (!getWorkGroup || getWorkGroup.err || !getWorkGroup.data) {
                    helpers.addResult(results, 3,
                        'Unable to describe Athena workgroup: ' + helpers.addError(getWorkGroup), region, arn);
                } else if (getWorkGroup.data.WorkGroup &&
                           getWorkGroup.data.WorkGroup.Configuration &&
                           getWorkGroup.data.WorkGroup.Configuration.ResultConfiguration &&
                           getWorkGroup.data.WorkGroup.Configuration.ResultConfiguration.EncryptionConfiguration &&
                           getWorkGroup.data.WorkGroup.Configuration.ResultConfiguration.EncryptionConfiguration.EncryptionOption) {
                    helpers.addResult(results, 0,
                        'Athena workgroup is using ' + getWorkGroup.data.WorkGroup.Configuration.ResultConfiguration.EncryptionConfiguration.EncryptionOption + ' encryption', region, arn);
                } else {
                    // Check for empty primary workgroups
                    if (wg.Name == 'primary' &&
                        (!getWorkGroup.data.WorkGroup ||
                         !getWorkGroup.data.WorkGroup.Configuration ||
                         !getWorkGroup.data.WorkGroup.Configuration.ResultConfiguration ||
                         !getWorkGroup.data.WorkGroup.Configuration.ResultConfiguration.OutputLocation)) {
                        helpers.addResult(results, 0, 'Athena primary workgroup does not have encryption enabled but is not in use.', region, arn);
                    } else {
                        helpers.addResult(results, 2, 'Athena workgroup is not using encryption', region, arn);
                    }
                }
            });
            rcb();
        }, function(){
            callback(null, results, source);
        });
    },

    remediate: function(config, cache, settings, resource, callback) {
        var putCall = this.actions.remediate;
        var pluginName = 'workgroupEncrypted';
        var wgNameArr = resource.split(':');
        var wgName = wgNameArr[wgNameArr.length - 1].split('/');
        wgName = wgName[wgName.length - 1];
        // find the location of the Kinesis wg needing to be remediated
        var wgLocation = wgNameArr[3];
        if (!wgLocation) {
            return callback('Unable to get wg location');
        }
        // add the location of the Kinesis wg to the config
        config.region = wgLocation;
        var params = {};
        // create the params necessary for the remediation
        if (settings.input && settings.input.encryptionOption){
            if (settings.input.encryptionOption === 'SSE_KMS' ||
                settings.input.encryptionOption === 'CSE_KMS') {
                if (settings.input.kmsKeyIdforWg){
                    params = {
                        WorkGroup: wgName,
                        ConfigurationUpdates: {
                            ResultConfigurationUpdates: {
                                EncryptionConfiguration: {
                                    EncryptionOption: settings.input.encryptionOption,
                                    KmsKey: settings.input.kmsKeyIdforWg
                                }
                            }
                        }
                    };
                } else {
                    return callback(`Key is mandatory for workgroup update with ${settings.input.encryptionOption}`);
                }

            } else if (settings.input.encryptionOption === 'SSE_S3'){
                params = {
                    WorkGroup: wgName,
                    ConfigurationUpdates: {
                        ResultConfigurationUpdates: {
                            EncryptionConfiguration: {
                                EncryptionOption: settings.input.encryptionOption,
                            }
                        }
                    }
                };
            }

        } else {
            return callback('EncryptionOption is mandatory for workgroup update');
        }

        var remediation_file = settings.remediation_file;

        remediation_file['pre_remediate']['actions'][pluginName][resource] = {
            'Encryption': 'Disabled',
            'Workgroup Name': wgName
        };

        // passes the config, put call, and params to the remediate helper function
        helpers.remediatePlugin(config, putCall[0], params, function(err) {
            if (err) {
                remediation_file['remediate']['actions'][pluginName]['error'] = err;
                return callback(err);
            }

            let action = params;
            action.action = putCall;

            remediation_file['post_remediate']['actions'][pluginName][resource] = action;
            remediation_file['remediate']['actions'][pluginName][resource] = {
                'Action': 'ENCRYPTED',
                'Workgroup Name': wgName
            };
            settings.remediation_file = remediation_file;
            return callback(null, action);
        });
    },

    rollback: function(config, cache, settings, resource, callback) {
        console.log('Rollback support for this plugin has not yet been implemented');
        console.log(config, cache, settings, resource);
        callback();
    }
};
