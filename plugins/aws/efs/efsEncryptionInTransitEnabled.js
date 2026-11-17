var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EFS Encryption In Transit Enabled',
    category: 'EFS',
    domain: 'Storage',
    severity: 'Medium',
    description: 'Ensures that EFS file systems use a file system policy to enforce encryption in transit.',
    more_info: 'Amazon EFS supports encryption of data in transit with TLS when a file system is mounted with the EFS mount helper or the tls mount option. ' +
        'Without a file system policy that denies requests made over an unencrypted connection (aws:SecureTransport is false), clients can still mount the file system without TLS.',
    link: 'https://docs.aws.amazon.com/efs/latest/ug/encryption-in-transit.html',
    recommended_action: 'Attach a file system policy to every EFS file system that denies all actions (Action "*") on the file system when the condition aws:SecureTransport is false, ' +
        'for example by enabling "Enforce in-transit encryption for all clients" in the file system policy.',
    apis: ['EFS:describeFileSystems', 'EFS:describeFileSystemPolicy'],
    settings: {
        efs_require_global_principal: {
            name: 'EFS Encryption In Transit Requires Global Principal',
            description: 'When set to true, the Deny statement that enforces encryption in transit must apply to all principals ("*"). ' +
                'When set to false, the principal of the statement is not evaluated.',
            regex: '^(true|false)$',
            default: 'false'
        }
    },
    realtime_triggers: ['efs:CreateFileSystem', 'efs:DeleteFileSystem', 'efs:PutFileSystemPolicy', 'efs:DeleteFileSystemPolicy'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var awsOrGov = helpers.defaultPartition(settings);

        var config = {
            requireGlobalPrincipal: (settings.efs_require_global_principal || this.settings.efs_require_global_principal.default) === 'true'
        };

        // The statement has to deny all actions on the file system when aws:SecureTransport is false, e.g.
        // { "Effect": "Deny", "Principal": { "AWS": "*" }, "Action": "*", "Resource": "<file system arn>",
        //   "Condition": { "Bool": { "aws:SecureTransport": "false" } } }
        function enforcesEncryptionInTransit(statement, fileSystemId) {
            if (statement.Effect !== 'Deny') return false;
            if (!Array.isArray(statement.Action) || statement.Action.indexOf('*') === -1) return false;

            var appliesToFileSystem = Array.isArray(statement.Resource) && statement.Resource.some(function(resource) {
                return typeof resource === 'string' && (resource === '*' || resource.indexOf(fileSystemId) > -1);
            });
            if (!appliesToFileSystem) return false;

            if (!statement.Condition || !statement.Condition.Bool) return false;
            var conditionKey = Object.keys(statement.Condition.Bool).find(function(key) {
                return key.toLowerCase() === 'aws:securetransport';
            });
            if (!conditionKey) return false;

            var value = statement.Condition.Bool[conditionKey];
            if (Array.isArray(value)) {
                if (value.length !== 1) return false;
                value = value[0];
            }
            if (String(value).toLowerCase() !== 'false') return false;

            if (config.requireGlobalPrincipal && !helpers.globalPrincipal(statement.Principal, settings)) return false;

            return true;
        }

        async.each(regions.efs, function(region, rcb) {
            var describeFileSystems = helpers.addSource(cache, source, ['efs', 'describeFileSystems', region]);

            if (!describeFileSystems) return rcb();

            if (describeFileSystems.err || !describeFileSystems.data) {
                helpers.addResult(results, 3,
                    'Unable to query for EFS file systems: ' + helpers.addError(describeFileSystems), region);
                return rcb();
            }

            if (!describeFileSystems.data.length) {
                helpers.addResult(results, 0, 'No EFS file systems present', region);
                return rcb();
            }

            describeFileSystems.data.forEach(function(fileSystem) {
                // arn:aws:elasticfilesystem:region:account-id:file-system/file-system-id
                var arn = fileSystem.FileSystemArn ||
                    'arn:' + awsOrGov + ':elasticfilesystem:' + region + ':' + fileSystem.OwnerId + ':file-system/' + fileSystem.FileSystemId;

                var describeFileSystemPolicy = helpers.addSource(cache, source,
                    ['efs', 'describeFileSystemPolicy', region, fileSystem.FileSystemId]);

                if (!describeFileSystemPolicy) {
                    helpers.addResult(results, 3,
                        'Unable to query for EFS file system policy: no data was collected', region, arn);
                    return;
                }

                if (describeFileSystemPolicy.err && describeFileSystemPolicy.err.code === 'PolicyNotFound') {
                    helpers.addResult(results, 2,
                        'EFS file system does not have a file system policy to enforce encryption in transit', region, arn);
                    return;
                }

                if (describeFileSystemPolicy.err || !describeFileSystemPolicy.data || !describeFileSystemPolicy.data.Policy) {
                    helpers.addResult(results, 3,
                        'Unable to query for EFS file system policy: ' + helpers.addError(describeFileSystemPolicy), region, arn);
                    return;
                }

                var statements = helpers.normalizePolicyDocument(describeFileSystemPolicy.data.Policy);

                if (statements && statements.some(function(statement) {
                    return enforcesEncryptionInTransit(statement, fileSystem.FileSystemId);
                })) {
                    helpers.addResult(results, 0,
                        'EFS file system policy enforces encryption in transit', region, arn);
                } else {
                    helpers.addResult(results, 2,
                        'EFS file system policy does not enforce encryption in transit', region, arn);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
