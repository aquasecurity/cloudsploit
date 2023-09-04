var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Access Approval Enabled',
    category: 'Security',
    domain: 'Management and Governance',
    description: 'Ensure that Access Approval is enabled for the project.',
    more_info: 'GCP Access Approval allows you to require the explicit approval of your organization whenever Google support try to access your projects. This adds an additional control and logging of who in your organization approved or denied the access requests.',
    link: 'https://cloud.google.com/cloud-provider-access-management/access-approval/docs/overview',
    recommended_action: 'Enable Access Approval for the GCP project.',
    apis: ['accessApproval:settings'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        let projects =  helpers.addSource(cache, source, 
            ['projects', 'get', 'global']);

        
        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }
        var project = projects.data[0].name;

        let accessApprovalSettings = helpers.addSource(cache, source, 
            ['accessApproval', 'settings', 'global']);

        if (!accessApprovalSettings || accessApprovalSettings.err || !accessApprovalSettings.data) {
            if (accessApprovalSettings.err && accessApprovalSettings.err.code === 404) {
                helpers.addResult(results, 2,
                    'Access Approval is not enabled for the project', 'global', project);
            } else {
                helpers.addResult(results, 3,
                    'Unable to query access approval settings for project: ' + helpers.addError(accessApprovalSettings), 'global', null, null, (accessApprovalSettings) ? accessApprovalSettings.err : null);
            }
            return callback(null, results, source);
        }

        if (accessApprovalSettings.data && accessApprovalSettings.data.length && accessApprovalSettings.data[0].enrolledServices) {
            helpers.addResult(results, 0,
                'Access Approval is enabled for the project', 'global', project);
        } else {
            helpers.addResult(results, 2,
                'Access Approval is not enabled for the project', 'global', project);
        }

        return callback(null, results, source);
    }
};
