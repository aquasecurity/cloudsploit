var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Instance Template Machine Type',
    category: 'Compute',
    description: 'Ensures that Google Cloud Virtual Machine instances are of given types.',
    more_info: 'Google Cloud Virtual Machine instance should be of the given types to ensure the internal compliance and prevent unexpected billing charges.',
    link: 'https://cloud.google.com/compute/docs/machine-types',
    recommended_action: 'Stop the Google Cloud Virtual Machine instance, change the machine type to the desired type  and restart the instance.',
    apis: ['instanceTemplates:list', 'projects:get'],
    settings: {
        instance_template_machine_types: {
            name: 'Instance Template Machine Types',
            description: 'Desired Google Cloud Virtual Machine instance template type',
            regex: '^.*$',
            default: ''
        },
    },
    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects', 'get', 'global']);
        var instance_template_machine_types = settings.instance_template_machine_types || this.settings.instance_template_machine_types.default;
        if (!instance_template_machine_types.length) return callback();
        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }
        
        var project = projects.data[0].name;
        async.each(regions.instanceTemplates, function (region, rcb) {
            let instanceTemplates = helpers.addSource(
                cache, source, ['instanceTemplates', 'list', region]);
            if (!instanceTemplates) return rcb();

            if (instanceTemplates.err || !instanceTemplates.data) {
                helpers.addResult(results, 3,
                    'Unable to query instance templates', region, null, null, instanceTemplates.err);
                return rcb();
            }

            if (!instanceTemplates.data.length) {
                helpers.addResult(results, 0, 'No instance templates found', region);
                return rcb();
            }
            instanceTemplates.data.forEach(instanceTemplate => {
                if (instanceTemplate.properties.machineType && instance_template_machine_types.includes(instanceTemplate.properties.machineType)) {
                    helpers.addResult(results, 0,
                        'Google Cloud Virtual Machine instance template has the desired machine type', region);
                } else {
                    helpers.addResult(results, 2,
                        'Google Cloud Virtual Machine instance template does not have the desired machine type', region);
                }
            });
            rcb();
        }, function () {
            callback(null, results, source);
        });
    }
};
