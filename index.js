var async = require('async');
var AWS = require('aws-sdk');

// AWS.config.update({
//     accessKeyId: '',
//     secretAccessKey: '',
//     sessionToken: '',
//     region: 'us-east-1'
// });

AWS.config.loadFromPath('./credentials.json');

var plugins = [
    // 'iam/rootMfaEnabled.js',
    // 'iam/usersMfaEnabled.js',
    // 'iam/passwordPolicy.js',
    // 'cloudtrail/cloudtrailEnabled.js',
    // 'ec2/elasticIpLimit.js',
    // 'cloudtrail/cloudtrailBucketDelete.js',
    // 'elb/sslExpiry.js'
];

async.eachSeries(plugins, function(pluginPath, callback){
    var plugin = require(__dirname + '/plugins/' + pluginPath);
    console.log('Running plugin: ' + plugin.title + '...');

    plugin.run(AWS, function(err, result){
        console.log(JSON.stringify(result, null, 2));
        callback(err);
    });
}, function(err, data){
    if (err) return console.log(err);
});
