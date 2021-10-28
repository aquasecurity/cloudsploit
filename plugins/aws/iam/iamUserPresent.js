
var helpers = require('../../../helpers/aws');
      
module.exports = {
    title: 'IAM User Present',
    category: 'IAM',
    description:  'Ensure that at least one IAM user exists so that access to your AWS services and resources is made only through IAM users instead of the root account.',
    more_info: 'To protect your AWS root account and adhere to IAM security best practices, create individual IAM users to access your AWS environment.',
    link: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
    recommended_action: 'Create IAM user(s) and use them to access AWS services and resources.',
    apis: ['IAM:listUsers'],
          
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
    
        var region = helpers.defaultRegion(settings);

        var listUsers = helpers.addSource(cache, source,
            ['iam', 'listUsers', region]);

        if (!listUsers) return callback(null, results, source);
    
        if (listUsers.err || !listUsers.data) {
            helpers.addResult(results, 3,
                'Unable to query for users: ' + helpers.addError(listUsers));
            return callback(null, results, source);
        }
    
        if (!listUsers.data.length) {
            helpers.addResult(results, 2, 'No users found', 'global');
        } else {
            helpers.addResult(results, 0, `Found ${listUsers.data.length} users`, 'global');
        }

        return callback(null, results, source);
    }  
};
   

         