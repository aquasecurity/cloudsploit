var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Default Tags For Resources',
    category: 'Logging and Monitoring',
    domain: 'Management and Governance',
    description: 'Ensures default tags are used on resources.',
    more_info: 'Having default tags like "CreatedBy" on resources help determine who created the resource in case of an accident.',
    link: 'https://docs.oracle.com/en-us/iaas/Content/Tagging/Tasks/managingtagdefaults.htm',
    recommended_action: 'Create default tags at the root compartment to ensure that all resources get tagged.',
    apis: ['defaultTags:list'],
   
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.objectFirstKey(cache['regionSubscription']['list']);

        var defaultTags = helpers.addSource(cache, source,
            ['defaultTags', 'list', region]);

        if (!defaultTags) return callback(null, results, source);

        if (defaultTags.err || !defaultTags.data) {
            helpers.addResult(results, 3,
                'Unable to query for default tags: ' + helpers.addError(defaultTags), region);
            return callback(null, results, source);
        }

        if (!defaultTags.data.length) {
            helpers.addResult(results, 2, 'No default tags found', region);
            return callback(null, results, source);
        }

        const compartment = defaultTags.data[0].compartmentId;
      
        const resourceTag = defaultTags.data.find(tag => 
            tag.value && tag.value === '${iam.principal.name}'
            && tag.lifecycleState && tag.lifecycleState === 'ACTIVE');
        
    
        if (resourceTag) {
            helpers.addResult(results, 0, 'Compartment is using default tags for resources', region, compartment);
        } else {
            helpers.addResult(results, 2, 'Compartment is not using default tags for resources', region, compartment);
        }
            
        callback(null, results, source);
    }
};