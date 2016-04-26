var async = require('async');

// OPTION 1: Configure AWS credentials through hard-coded key and secret
// var AWSConfig = {
//     accessKeyId: '',
//     secretAccessKey: '',
//     sessionToken: '',
//     region: 'us-east-1'
// };

// OPTION 2: Import an AWS config file containing credentials
// var AWSConfig = require(__dirname + '/credentials.json');
var AWSConfig = require(__dirname + '/../../../cloudsploit-secure/scan-self.json');

// OPTION 3: Set AWS credentials in environment variables

var tests = [
    // 'iam/rootMfaEnabled.js',
    // 'iam/rootAccessKeys.js',
    // 'iam/rootAccountInUse.js',
    // 'iam/usersMfaEnabled.js',
    // 'iam/minPasswordLength.js',
    // 'iam/maxPasswordAge.js',
    // 'iam/passwordExpiration.js',
    // 'iam/passwordRequiresLowercase.js',
    // 'iam/passwordRequiresUppercase.js',
    // 'iam/passwordRequiresNumbers.js',
    // 'iam/passwordRequiresSymbols.js',
    // 'iam/passwordReusePrevention.js',
    // 'iam/accessKeysRotated.js',
    // 'iam/accessKeysLastUsed.js',
    // 'iam/accessKeysExtra.js',
    // 'iam/sshKeysRotated.js',
    // 'iam/emptyGroups.js',
    // 'iam/certificateExpiry.js',
    // 'cloudtrail/cloudtrailEnabled.js',
    // 'cloudtrail/cloudtrailBucketDelete.js',
    // 'cloudtrail/cloudtrailFileValidation.js',
    // 'ec2/elasticIpLimit.js',
    // 'ec2/vpcElasticIpLimit.js',
    // 'ec2/instanceLimit.js',
    // 'ec2/insecureCiphers.js',
    // 'vpc/classicInstances.js',
    // 'ec2/excessiveSecurityGroups.js',
    // 'ec2/openFTP.js',
    // 'ec2/openSSH.js',
    // 'ec2/openTelnet.js',
    // 'ec2/openCIFS.js',
    // 'ec2/openDNS.js',
    // 'ec2/openMySQL.js',
    // 'ec2/openNetBIOS.js',
    // 'ec2/openPostgreSQL.js',
    // 'ec2/openRDP.js',
    // 'ec2/openRPC.js',
    // 'ec2/openSMBoTCP.js',
    // 'ec2/openSMTP.js',
    // 'ec2/openSQLServer.js',
    // 'ec2/openVNCClient.js',
    // 'ec2/openVNCServer.js',
    // 's3/bucketAllUsersPolicy.js',
    // 'route53/domainAutoRenew.js',
    // 'route53/domainTransferLock.js',
    // 'route53/domainExpiry.js',
    // 'rds/rdsEncryptionEnabled.js',
    // 'rds/rdsAutomatedBackups.js',
    // 'rds/rdsPubliclyAccessible.js',
    // 'rds/rdsRestorable.js',
    // 'kms/kmsKeys.js'
];

console.log('CATEGORY\tTEST\t\t\t\tRESOURCE\t\t\tREGION\t\tSTATUS\tMESSAGE');

async.eachSeries(tests, function(testPath, callback){
    var test = require(__dirname + '/plugins/' + testPath);

    test.run(AWSConfig, function(err, results){
        //console.log(JSON.stringify(result, null, 2));
        
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
            console.log(test.category + '\t' + test.title + '\t' + (results[r].resource || 'N/A') + '\t' + (results[r].region || 'Global') + '\t\t' + statusWord + '\t' + results[r].message);
        }

        callback(err);
    });
}, function(err, data){
    if (err) return console.log(err);
});
