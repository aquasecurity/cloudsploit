var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Instance Template Machine Type',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensure that Cloud Virtual Machine instance templates are of given types.',
    more_info: 'Virtual Machine instance templates should be of the given types to ensure the internal compliance and prevent unexpected billing charges.',
    link: 'https://cloud.google.com/compute/docs/machine-types',
    recommended_action: 'Ensure that Virtual Machine instance templates are not using undesired machine types.',
    apis: ['instanceTemplates:list', 'projects:get'],
    settings: {
        instance_template_machine_types: {
            name: 'Instance Template Machine Types',
            description: 'Desired Google Cloud Virtual Machine instance template type',
            regex: '^.*$',
            default: ''
        },
    },
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        var instance_template_machine_types = settings.instance_template_machine_types || this.settings.instance_template_machine_types.default;

        if (!instance_template_machine_types.length) return callback(null, results, source);

        let projects = helpers.addSource(cache, source,
            ['projects', 'get', 'global']);
        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }
        async.each(regions.instanceTemplates, function(region, rcb) {
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
                if (instanceTemplate.properties && instanceTemplate.properties.machineType && instance_template_machine_types.includes(instanceTemplate.properties.machineType)) {
                    helpers.addResult(results, 0,
                        'Virtual Machine instance template has desired machine type', region);
                } else {
                    helpers.addResult(results, 2,
                        'Virtual Machine instance template does not have desired machine type', region);
                }
            });
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
