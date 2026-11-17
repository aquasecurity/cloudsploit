var expect = require('chai').expect;
var eventBridgeArchiveEncrypted = require('./eventBridgeArchiveEncrypted');

const region = 'eu-west-1';
const archiveName = 'my-archive';
const archiveArn = 'arn:aws:events:eu-west-1:123456789012:archive/' + archiveName;
const keyId = '11111111-2222-3333-4444-555555555555';
const keyArn = 'arn:aws:kms:eu-west-1:123456789012:key/' + keyId;

const key = (manager) => ({ data: { KeyMetadata: { KeyId: keyId, Origin: 'AWS_KMS', KeyManager: manager || 'CUSTOMER' } } });

const createCache = (listArchives, describeArchive, describeKey, aliases) => ({
    eventbridge: {
        listArchives: { [region]: listArchives },
        describeArchive: { [region]: describeArchive || {} }
    },
    kms: {
        listAliases: { [region]: { data: aliases || [] } },
        describeKey: { [region]: describeKey || {} }
    }
});

const archives = { data: [{ ArchiveName: archiveName, ArchiveArn: archiveArn }] };
const archiveWith = (kmsKeyIdentifier) => ({ [archiveName]: { data: { ArchiveName: archiveName, ArchiveArn: archiveArn, KmsKeyIdentifier: kmsKeyIdentifier } } });

const run = (cache, settings) => {
    let output;
    eventBridgeArchiveEncrypted.run(cache, settings || {}, (err, results) => { output = results; });
    return output;
};

describe('eventBridgeArchiveEncrypted', function () {
    it('should PASS when the archive uses a customer managed key', function () {
        const results = run(createCache(archives, archiveWith(keyArn), { [keyId]: key('CUSTOMER') }));

        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(0);
        expect(results[0].resource).to.equal(archiveArn);
    });

    it('should resolve an alias to the key', function () {
        const aliases = [{ AliasName: 'alias/events', AliasArn: 'arn:aws:kms:eu-west-1:123456789012:alias/events', TargetKeyId: keyId }];
        const results = run(createCache(archives, archiveWith('alias/events'), { [keyId]: key('CUSTOMER') }, aliases));

        expect(results[0].status).to.equal(0);
    });

    it('should FAIL when the archive has no KMS key', function () {
        const results = run(createCache(archives, archiveWith(undefined)));

        expect(results[0].status).to.equal(2);
        expect(results[0].message).to.include('not encrypted with a KMS key');
    });

    it('should FAIL when an AWS managed key is used but a customer managed key is required', function () {
        const results = run(createCache(archives, archiveWith(keyArn), { [keyId]: key('AWS') }));

        expect(results[0].status).to.equal(2);
        expect(results[0].message).to.include('less than the desired encryption level awscmk');
    });

    it('should PASS with an AWS managed key when that is the desired level', function () {
        const results = run(createCache(archives, archiveWith(keyArn), { [keyId]: key('AWS') }),
            { eventbridge_archive_desired_encryption_level: 'awskms' });

        expect(results[0].status).to.equal(0);
    });

    it('should evaluate every archive', function () {
        const two = { data: [{ ArchiveName: archiveName }, { ArchiveName: 'other' }] };
        const describe = Object.assign(archiveWith(keyArn), { other: { data: { ArchiveName: 'other' } } });
        const results = run(createCache(two, describe, { [keyId]: key('CUSTOMER') }));

        expect(results.map((r) => r.status).sort()).to.deep.equal([0, 2]);
    });

    it('should PASS when there are no archives', function () {
        const results = run(createCache({ data: [] }));

        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(0);
    });

    it('should return UNKNOWN when archives cannot be listed', function () {
        const results = run(createCache({ err: { message: 'AccessDenied' } }));

        expect(results[0].status).to.equal(3);
    });

    it('should return UNKNOWN when the archive was not described', function () {
        const results = run(createCache(archives, {}));

        expect(results[0].status).to.equal(3);
    });

    it('should return UNKNOWN when the key cannot be described', function () {
        const results = run(createCache(archives, archiveWith(keyArn), {}));

        expect(results[0].status).to.equal(3);
    });
});
