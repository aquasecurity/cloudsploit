var async = require('async');
var plugins = require('./exports.js');

// OPTION 1: Configure AWS credentials through hard-coded key and secret
// var AWSConfig = {
//     accessKeyId: '',
//     secretAccessKey: '',
//     sessionToken: '',
//     region: 'us-east-1'
// };

// OPTION 2: Import an AWS config file containing credentials
// var AWSConfig = require(__dirname + '/credentials.json');

// OPTION 3: Set AWS credentials in environment variables

console.log('CATEGORY\tPLUGIN\t\t\t\tRESOURCE\t\t\tREGION\t\tSTATUS\tMESSAGE');

async.forEachOfLimit(plugins, 10, function(plugin, key, callback){
    plugin.run(AWSConfig, function(err, results){        
        for (r in results) {
            var statusWord;
            if (results[r].status === 0) {
                statusWord = 'OK';
            } else if (results[r].status === 1) {
                statusWord = 'WARN';
            } else if (results[r].status === 2) {
                statusWord = 'FAIL';
            } else {
                statusWord = 'UNKNOWN';
            }
            console.log(plugin.category + '\t' + plugin.title + '\t' + (results[r].resource || 'N/A') + '\t' + (results[r].region || 'Global') + '\t\t' + statusWord + '\t' + results[r].message);
        }

        callback(err);
    });
}, function(err, data){
    if (err) return console.log(err);
});
