const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Machine Learning Workspace CMK Encrypted',
    category: 'MySQL Server',
    domain: 'Databases',
    severity: 'High',
    description: 'Ensures that Machine Learning Workspaces are encrypted using CMK.',
    more_info: 'Azure Machine Learning allows you to encrypt workspaces using customer-managed keys (CMK) instead of using platform-managed keys, which are enabled by default. Using CMK encryption offers enhanced security and compliance, allowing centralized management and control of encryption keys through Azure Key Vault.',
    recommended_action: 'Ensure that Machine Learning Workspaces are encrypted using CMK.',
    link: 'https://learn.microsoft.com/en-us/azure/machine-learning/concept-customer-managed-keys',
    apis: ['machineLearning:listWorkspaces'],   
    realtime_triggers: ['microsoft:machinelearningservices:workspaces:write', 'microsoft:machinelearningservices:workspaces:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.machineLearning, function(location, rcb) {
            var machineLearningWorkspaces = helpers.addSource(cache, source,
                ['machineLearning', 'listWorkspaces', location]);

            if (!machineLearningWorkspaces) return rcb();

            if (machineLearningWorkspaces.err || !machineLearningWorkspaces.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Machine Learning workspaces: ' + helpers.addError(machineLearningWorkspaces), location);
                return rcb();
            }

            if (!machineLearningWorkspaces.data.length) {
                helpers.addResult(results, 0, 'No existing Machine Learning workspaces found', location);
                return rcb();
            }

            for (let workspace of machineLearningWorkspaces.data) {
                if (!workspace.id) continue; 

                if (workspace.encryption && workspace.encryption.keyVaultProperties && workspace.encryption.keyVaultProperties.keyIdentifier) {
                    helpers.addResult(results, 0, 'Machine Learning workspace is encrypted using CMK', location, workspace.id);
                } else {
                    helpers.addResult(results, 2, 'Machine Learning workspace is not encrypted using CMK', location, workspace.id);
                }
            }
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
