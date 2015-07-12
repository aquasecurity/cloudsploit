var async = require('async');

// var AWSConfig = {
//     accessKeyId: '',
//     secretAccessKey: '',
//     sessionToken: '',
//     region: 'us-east-1'
// };

var AWSConfig = require('./credentials.json');

var plugins = [
    'iam/rootAccountSecurity.js',
    'iam/usersMfaEnabled.js',
    'iam/passwordPolicy.js',
    'cloudtrail/cloudtrailEnabled.js',
    'cloudtrail/cloudtrailBucketDelete.js',
    'ec2/accountLimits.js',
    'elb/certificateExpiry.js',
    'elb/insecureCiphers.js',
    'vpc/detectClassic.js',
    'ec2/openPorts.js'
];

console.log('CATEGORY\tPLUGIN\t\t\tTEST\t\t\tSTATUS\tMESSAGE');

async.eachSeries(plugins, function(pluginPath, callback){
    var plugin = require(__dirname + '/plugins/' + pluginPath);

    plugin.run(AWSConfig, function(err, result){
        //console.log(JSON.stringify(result, null, 2));
        for (i in result.tests) {
            for (j in result.tests[i].results) {
                var statusWord;
                if (result.tests[i].results[j].status === 0) {
                    statusWord = 'OK';
                } else if (result.tests[i].results[j].status === 1) {
                    statusWord = 'WARN';
                } else if (result.tests[i].results[j].status === 2) {
                    statusWord = 'FAIL';
                } else {
                    statusWord = 'UNKNOWN';
                }
                console.log(result.category + '\t\t' + result.title + '\t' + result.tests[i].title + '\t' + statusWord + '\t' + result.tests[i].results[j].message);
            }
        }
        callback(err);
    });
}, function(err, data){
    if (err) return console.log(err);
});
