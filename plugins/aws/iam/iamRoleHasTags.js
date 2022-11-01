var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'IAM Role Has Tags',
    category: 'IAM',
    domain: 'Identity and Access management',
    description: 'Ensure that AWS IAM Roles have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html',
    recommended_action: 'Modify Roles to add tags.',
    apis: ['IAM:listRoles', 'IAM:getRole'],
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);

        var listRoles = helpers.addSource(cache, source,
            ['iam', 'listRoles', region]);

        if (!listRoles) return callback(null, results, source);

        if (listRoles.err || !listRoles.data) {
            helpers.addResult(results, 3,
                'Unable to query for IAM roles: ' + helpers.addError(listRoles));
            return callback(null, results, source);
        }

        if (!listRoles.data.length) {
            helpers.addResult(results, 0, 'No IAM roles found');
            return callback(null, results, source);
        }
        
        for (var role of listRoles.data) {
            if (!role.RoleName) continue;

            var getRole = helpers.addSource(cache, source,
                ['iam', 'getRole', region, role.RoleName]);
              
            if (!getRole || getRole.err || !getRole.data || !getRole.data.Role) {
                helpers.addResult(results, 3,
                    'Unable to query for IAM role details: ' + role.RoleName + ': ' + helpers.addError(getRole), 'global', role.Arn);
                continue;
            }
            
            if (!getRole.data.Role.Tags || !getRole.data.Role.Tags.length) {
                helpers.addResult(results, 2, 'IAM Role does not have tags', 'global', role.Arn);
            } else {
                helpers.addResult(results, 0, 'IAM Role has tags', 'global', role.Arn);
            } 

        }
        
        return callback(null, results, source);
    }
};