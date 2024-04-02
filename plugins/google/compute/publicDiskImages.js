var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Public Disk Images',
    category: 'Compute',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensure that your disk images are not being shared publicly.',
    more_info: 'To avoid exposing sensitive information, make sure that your virtual machine disk images are not being publicly shared with all other GCP accounts.',
    link: 'https://cloud.google.com/compute/docs/images',
    recommended_action: 'Ensure that your VM disk images are not accessible by allUsers or allAuthenticatedUsers.',
    apis: ['images:list', 'images:getIamPolicy'],
    realtime_triggers: ['compute.images.insert', 'compute.images.delete'],
    
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        let projects = helpers.addSource(cache, source,
            ['projects', 'get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0].name;

        let images = helpers.addSource(cache, source,
            ['images', 'list', 'global']);

        if (!images || images.err || !images.data) {
            helpers.addResult(results, 3, 'Unable to query Disk Images: ' + helpers.addError(images), 'global');
            return callback(null, results, source);
        }

        if (!images.data.length) {
            helpers.addResult(results, 0, 'No Disk Images found', 'global');
            return callback(null, results, source);
        }
        
        let getImagesIamPolicies = helpers.addSource(cache, source,
            ['images', 'getIamPolicy', 'global']);

        if (!getImagesIamPolicies || getImagesIamPolicies.err || !getImagesIamPolicies.data) {
            helpers.addResult(results, 3, 'Unable to query IAM Policies for Disk Images: ' + helpers.addError(getImagesIamPolicies), 'global');
            return callback(null, results, source);
        }

        if (!getImagesIamPolicies.data.length) {
            helpers.addResult(results, 0, 'No IAM Policies found', 'global');
            return callback(null, results, source);
        }

        getImagesIamPolicies = getImagesIamPolicies.data;

        images.data.forEach(image => {

            let imageIamPolicy = getImagesIamPolicies.find(iamPolicy => iamPolicy.parent && iamPolicy.parent.id === image.id);

            let resource = helpers.createResourceName('images', image.name, project, 'global');

            if (!imageIamPolicy || !imageIamPolicy.bindings || !imageIamPolicy.bindings.length) {
                helpers.addResult(results, 0,
                    'No IAM Policies found for disk image', 'global', resource);
            } else {
                var allowedAllUsers = false;
                imageIamPolicy.bindings.forEach(roleBinding => {
                    if (roleBinding.role && roleBinding.members && roleBinding.members.length && (roleBinding.members.includes('allUsers') || roleBinding.members.includes('allAuthenticatedUsers'))) {
                        allowedAllUsers = true;
                    }
                });
                if (!allowedAllUsers) {
                    helpers.addResult(results, 0, 'Disk Image is not publicly accessible', 'global', resource);
                } else {
                    helpers.addResult(results, 2, 'Disk Image is publicly accessible', 'global', resource);
                }
            }
        });
        callback(null, results, source);
    }
};