var expect = require('chai').expect;
var plugin = require('./glueDevEndpointSecurityConfiguration');

const region = 'eu-west-1';
const createCache = (data) => ({
    sts: { getCallerIdentity: { 'us-east-1': { data: '123456789012' } } },
    glue: { getDevEndpoints: { [region]: data } }
});
const run = (cache, settings) => {
    let output;
    plugin.run(cache, settings || {}, (err, results) => { output = results; });
    return output;
};

describe('glueDevEndpointSecurityConfiguration', function () {
    it('should PASS when the development endpoint has a security configuration', function () {
        const results = run(createCache({ data: [{ EndpointName: 'x1', SecurityConfiguration: 'any' }] }));

        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(0);
        expect(results[0].resource).to.equal('arn:aws:glue:eu-west-1:123456789012:devEndpoint/x1');
    });

    it('should FAIL when the development endpoint has no security configuration', function () {
        const results = run(createCache({ data: [{ EndpointName: 'x1' }] }));

        expect(results[0].status).to.equal(2);
    });

    it('should PASS when the configuration matches the required name', function () {
        const results = run(createCache({ data: [{ EndpointName: 'x1', SecurityConfiguration: 'tkp-security-configuration' }] }),
            { glue_dev_endpoint_security_configuration: 'tkp-security-configuration' });

        expect(results[0].status).to.equal(0);
    });

    it('should FAIL when the configuration differs from the required name', function () {
        const results = run(createCache({ data: [{ EndpointName: 'x1', SecurityConfiguration: 'other' }] }),
            { glue_dev_endpoint_security_configuration: 'tkp-security-configuration' });

        expect(results[0].status).to.equal(2);
        expect(results[0].message).to.include('instead of');
    });

    it('should PASS when there are none', function () {
        expect(run(createCache({ data: [] }))[0].status).to.equal(0);
    });

    it('should return UNKNOWN when they cannot be listed', function () {
        expect(run(createCache({ err: { message: 'AccessDenied' } }))[0].status).to.equal(3);
    });
});
