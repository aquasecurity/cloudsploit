module.exports = {
    title: 'Privilege Analysis',
    category: 'Virtual Machines',
    domain: 'Compute',
    severity: 'Info',
    description: 'Ensures that no virtual machines in your Azure environment have excessive permissions.',
    more_info: 'Virtual machines that use managed identities with excessive Azure AD permissions may pose security risks. It is a best practice to assign only the necessary permissions to the managed identities attached to virtual machines.',
    link: 'https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/how-to-use-vm-token',
    recommended_action: 'Review and restrict the Azure AD roles associated with managed identities used by virtual machines to follow the principle of least privilege.',
    apis: [''],
    realtime_triggers: [
        'Microsoft.Compute/virtualMachines/write',
        'Microsoft.Compute/virtualMachines/delete',
        'Microsoft.ManagedIdentity/userAssignedIdentities/assign/action',
    ],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        callback(null, results, source);
    },
};
