var expect = require('chai').expect;
var efsEncryptionInTransitEnabled = require('./efsEncryptionInTransitEnabled');

const region = 'eu-west-1';
const fileSystemId = 'fs-0123456789abcdef0';
const arn = 'arn:aws:elasticfilesystem:eu-west-1:123456789012:file-system/' + fileSystemId;

const fileSystem = (id) => ({
    FileSystemId: id || fileSystemId,
    FileSystemArn: 'arn:aws:elasticfilesystem:eu-west-1:123456789012:file-system/' + (id || fileSystemId),
    OwnerId: '123456789012'
});

const denyInsecureTransport = (overrides) => Object.assign({
    Effect: 'Deny',
    Principal: { AWS: '*' },
    Action: '*',
    Resource: arn,
    Condition: { Bool: { 'aws:SecureTransport': 'false' } }
}, overrides);

const policy = (statements) => ({ data: { FileSystemId: fileSystemId, Policy: JSON.stringify({ Version: '2012-10-17', Statement: statements }) } });

const createCache = (fileSystems, policies) => ({
    efs: {
        describeFileSystems: { [region]: fileSystems },
        describeFileSystemPolicy: { [region]: policies }
    }
});

const run = (cache, settings) => {
    let output;
    efsEncryptionInTransitEnabled.run(cache, settings || {}, (err, results) => { output = results; });
    return output;
};

describe('efsEncryptionInTransitEnabled', function () {
    describe('run', function () {
        it('should PASS when a policy denies all actions without secure transport', function () {
            const results = run(createCache({ data: [fileSystem()] }, { [fileSystemId]: policy([denyInsecureTransport()]) }));

            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(0);
            expect(results[0].region).to.equal(region);
            expect(results[0].resource).to.equal(arn);
            expect(results[0].message).to.include('enforces encryption in transit');
        });

        it('should PASS when Action and Resource are arrays and the policy has other statements', function () {
            const allow = { Effect: 'Allow', Principal: { AWS: '*' }, Action: ['elasticfilesystem:ClientMount'], Resource: arn };
            const results = run(createCache({ data: [fileSystem()] }, {
                [fileSystemId]: policy([allow, denyInsecureTransport({ Action: ['*'], Resource: [arn] })])
            }));

            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(0);
        });

        it('should PASS when the condition value is a boolean or an array', function () {
            const asBoolean = run(createCache({ data: [fileSystem()] }, {
                [fileSystemId]: policy([denyInsecureTransport({ Condition: { Bool: { 'aws:SecureTransport': false } } })])
            }));
            const asArray = run(createCache({ data: [fileSystem()] }, {
                [fileSystemId]: policy([denyInsecureTransport({ Condition: { Bool: { 'aws:SecureTransport': ['false'] } } })])
            }));

            expect(asBoolean[0].status).to.equal(0);
            expect(asArray[0].status).to.equal(0);
        });

        it('should PASS when the resource is a wildcard', function () {
            const results = run(createCache({ data: [fileSystem()] }, { [fileSystemId]: policy([denyInsecureTransport({ Resource: '*' })]) }));

            expect(results[0].status).to.equal(0);
        });

        it('should FAIL when the file system has no policy', function () {
            const results = run(createCache({ data: [fileSystem()] }, { [fileSystemId]: { err: { code: 'PolicyNotFound', message: 'no policy' } } }));

            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(2);
            expect(results[0].resource).to.equal(arn);
            expect(results[0].message).to.include('does not have a file system policy');
        });

        it('should FAIL when the policy only allows access', function () {
            const allow = { Effect: 'Allow', Principal: { AWS: '*' }, Action: '*', Resource: arn, Condition: { Bool: { 'aws:SecureTransport': 'false' } } };
            const results = run(createCache({ data: [fileSystem()] }, { [fileSystemId]: policy([allow]) }));

            expect(results[0].status).to.equal(2);
            expect(results[0].message).to.include('does not enforce encryption in transit');
        });

        it('should FAIL when the deny statement has no condition', function () {
            const results = run(createCache({ data: [fileSystem()] }, { [fileSystemId]: policy([denyInsecureTransport({ Condition: undefined })]) }));

            expect(results[0].status).to.equal(2);
        });

        it('should FAIL when the condition denies only secure transport', function () {
            const results = run(createCache({ data: [fileSystem()] }, {
                [fileSystemId]: policy([denyInsecureTransport({ Condition: { Bool: { 'aws:SecureTransport': 'true' } } })])
            }));

            expect(results[0].status).to.equal(2);
        });

        it('should FAIL when the deny statement does not cover all actions', function () {
            const results = run(createCache({ data: [fileSystem()] }, {
                [fileSystemId]: policy([denyInsecureTransport({ Action: 'elasticfilesystem:ClientMount' })])
            }));

            expect(results[0].status).to.equal(2);
        });

        it('should FAIL when the deny statement is for another file system', function () {
            const other = 'arn:aws:elasticfilesystem:eu-west-1:123456789012:file-system/fs-99999999999999999';
            const results = run(createCache({ data: [fileSystem()] }, { [fileSystemId]: policy([denyInsecureTransport({ Resource: other })]) }));

            expect(results[0].status).to.equal(2);
        });

        it('should FAIL when the policy is not valid JSON', function () {
            const results = run(createCache({ data: [fileSystem()] }, { [fileSystemId]: { data: { Policy: 'not json' } } }));

            expect(results[0].status).to.equal(2);
        });

        it('should ignore the principal by default', function () {
            const results = run(createCache({ data: [fileSystem()] }, {
                [fileSystemId]: policy([denyInsecureTransport({ Principal: { AWS: 'arn:aws:iam::123456789012:role/app' } })])
            }));

            expect(results[0].status).to.equal(0);
        });

        it('should FAIL for a specific principal when a global principal is required', function () {
            const settings = { efs_require_global_principal: 'true' };
            const specific = run(createCache({ data: [fileSystem()] }, {
                [fileSystemId]: policy([denyInsecureTransport({ Principal: { AWS: 'arn:aws:iam::123456789012:role/app' } })])
            }), settings);
            const global = run(createCache({ data: [fileSystem()] }, { [fileSystemId]: policy([denyInsecureTransport()]) }), settings);

            expect(specific[0].status).to.equal(2);
            expect(global[0].status).to.equal(0);
        });

        it('should evaluate every file system', function () {
            const second = 'fs-0fedcba9876543210';
            const results = run(createCache({ data: [fileSystem(), fileSystem(second)] }, {
                [fileSystemId]: policy([denyInsecureTransport()]),
                [second]: { err: { code: 'PolicyNotFound' } }
            }));

            expect(results.length).to.equal(2);
            expect(results.filter((r) => r.status === 0).length).to.equal(1);
            expect(results.filter((r) => r.status === 2).length).to.equal(1);
        });

        it('should PASS when there are no file systems', function () {
            const results = run(createCache({ data: [] }, {}));

            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(0);
            expect(results[0].message).to.equal('No EFS file systems present');
        });

        it('should return UNKNOWN when the file systems cannot be listed', function () {
            const results = run(createCache({ err: { message: 'AccessDeniedException' } }, {}));

            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(3);
            expect(results[0].message).to.include('Unable to query for EFS file systems');
        });

        it('should return UNKNOWN when the policy cannot be read for another reason than a missing policy', function () {
            const results = run(createCache({ data: [fileSystem()] }, { [fileSystemId]: { err: { code: 'ThrottlingException', message: 'slow down' } } }));

            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(3);
            expect(results[0].message).to.include('Unable to query for EFS file system policy');
        });

        it('should return UNKNOWN when the policy was not collected for a file system', function () {
            const results = run(createCache({ data: [fileSystem()] }, {}));

            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(3);
            expect(results[0].resource).to.equal(arn);
            expect(results[0].message).to.include('no data was collected');
        });

        it('should not return results when no data was collected', function () {
            const results = run({ efs: { describeFileSystems: {} } });

            expect(results.length).to.equal(0);
        });
    });
});
