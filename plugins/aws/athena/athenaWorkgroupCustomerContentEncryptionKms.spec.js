var expect = require('chai').expect;
var plugin = require('./athenaWorkgroupCustomerContentEncryptionKms');

const region = 'eu-west-1';
const keyArn = 'arn:aws:kms:eu-west-1:123456789012:key/11111111-2222-3333-4444-555555555555';

const workGroup = (configuration) => ({ data: { WorkGroup: { Configuration: configuration } } });
const createCache = (workGroups, getWorkGroup, listKeys) => ({
    sts: { getCallerIdentity: { 'us-east-1': { data: '123456789012' } } },
    athena: { listWorkGroups: { [region]: workGroups }, getWorkGroup: { [region]: getWorkGroup || {} } },
    kms: { listKeys: { [region]: listKeys || { data: [{ KeyId: '11111111-2222-3333-4444-555555555555', KeyArn: keyArn }] } } }
});
const run = (cache) => {
    let output;
    plugin.run(cache, {}, (err, results) => { output = results; });
    return output;
};
const wgs = { data: [{ Name: 'wg1' }] };

describe('athenaWorkgroupCustomerContentEncryptionKms', function () {
    it('should PASS when the customer content uses a key of the account', function () {
        const results = run(createCache(wgs, { wg1: workGroup({ CustomerContentEncryptionConfiguration: { KmsKey: keyArn } }) }));

        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(0);
    });

    it('should FAIL without customer content encryption', function () {
        expect(run(createCache(wgs, { wg1: workGroup({}) }))[0].status).to.equal(2);
    });

    it('should FAIL when only the result location is encrypted', function () {
        const results = run(createCache(wgs, { wg1: workGroup({ ResultConfiguration: { EncryptionConfiguration: { EncryptionOption: 'SSE_KMS', KmsKey: keyArn } } }) }));

        expect(results[0].status).to.equal(2);
    });

    it('should FAIL when the key is not a key of the account', function () {
        const other = 'arn:aws:kms:eu-west-1:999999999999:key/aaaaaaaa-2222-3333-4444-555555555555';

        expect(run(createCache(wgs, { wg1: workGroup({ CustomerContentEncryptionConfiguration: { KmsKey: other } }) }))[0].status).to.equal(2);
    });

    it('should not evaluate the primary workgroup', function () {
        expect(run(createCache({ data: [{ Name: 'primary' }] }))[0].message).to.include('not evaluated');
    });

    it('should PASS without workgroups', function () {
        expect(run(createCache({ data: [] }))[0].status).to.equal(0);
    });

    it('should return UNKNOWN when workgroups cannot be listed', function () {
        expect(run(createCache({ err: { message: 'AccessDenied' } }))[0].status).to.equal(3);
    });

    it('should return UNKNOWN when the workgroup cannot be described', function () {
        expect(run(createCache(wgs, {}))[0].status).to.equal(3);
    });
});
