module.exports = {
    title: 'Privilege Analysis',
    category: 'Compute',
    domain: 'Compute',
    severity: 'Info',
    description: 'Ensures that no compute instances in your cloud has excessive permissions.',
    more_info: 'Compute instances having service account attached with excessive permissions can lead to security risks. Compute instances should have restrictive permissions assigned through service accounts for security best practices.',
    link: 'https://cloud.google.com/compute/docs/access/iam',
    recommended_action: 'Make sure that compute instances are using service account with only required permissions.',
    apis: [''],
    realtime_triggers: ['compute.instances.insert', 'compute.instances.delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        callback(null, results, source);

    }
};
