module.exports = {
    title: 'Privilege Analysis',
    category: 'App Service',
    domain: 'Web Apps',
    severity: 'Info',
    description: 'Ensures that no Azure Functions in your environment have excessive permissions.',
    more_info: 'Azure Functions that use managed identities or service principals with excessive Azure AD permissions may pose security risks. It is a best practice to assign only the necessary permissions to the identities attached to functions.',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/overview-managed-identity',
    recommended_action: 'Review and restrict the Azure AD roles associated with managed identities used by Azure Functions to follow the principle of least privilege.',
    apis: [''],
    realtime_triggers: [
        'Microsoft.Web/sites/write',
        'Microsoft.Web/sites/delete',
        'Microsoft.Web/sites/functions/write',
        'Microsoft.Web/sites/functions/delete',
    ],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        callback(null, results, source);
    },
};
